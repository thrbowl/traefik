package provider

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/BurntSushi/ty/fun"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/cenk/backoff"
	"github.com/containous/traefik/job"
	"github.com/containous/traefik/log"
	"github.com/containous/traefik/safe"
	"github.com/containous/traefik/types"
)

var _ Provider = (*ECS)(nil)

// ECS holds configurations of the ECS provider.
type ECS struct {
	BaseProvider `mapstructure:",squash"`

	Domain           string `description:"Default domain used"`
	ExposedByDefault bool   `description:"Expose containers by default"`
	RefreshSeconds   int    `description:"Polling interval (in seconds)"`

	// ECS lookup parameters
	Cluster         string `description:"ECS Cluster Name"`
	Region          string `description:"The AWS region to use for requests"`
	AccessKeyID     string `description:"The AWS credentials access key to use for making requests"`
	SecretAccessKey string `description:"The AWS credentials access key to use for making requests"`
}

type ecsInstance struct {
	Name                string
	ID                  string
	task                *ecs.Task
	taskDefinition      *ecs.TaskDefinition
	container           *ecs.Container
	containerDefinition *ecs.ContainerDefinition
	machine             *ec2.Instance
}

type awsClient struct {
	ecs *ecs.ECS
	ec2 *ec2.EC2
}

func (provider *ECS) createClient() (*awsClient, error) {
	sess := session.New()
	ec2meta := ec2metadata.New(sess)
	if provider.Region == "" {
		log.Infoln("No EC2 region provided, querying instance metadata endpoint...")
		identity, err := ec2meta.GetInstanceIdentityDocument()
		if err != nil {
			return nil, err
		}
		provider.Region = identity.Region
	}

	cfg := &aws.Config{
		Region: &provider.Region,
		Credentials: credentials.NewChainCredentials(
			[]credentials.Provider{
				&credentials.StaticProvider{
					Value: credentials.Value{
						AccessKeyID:     provider.AccessKeyID,
						SecretAccessKey: provider.SecretAccessKey,
					},
				},
				&credentials.EnvProvider{},
				&credentials.SharedCredentialsProvider{},
				defaults.RemoteCredProvider(*(defaults.Config()), defaults.Handlers()),
			}),
	}

	return &awsClient{
		ecs.New(sess, cfg),
		ec2.New(sess, cfg),
	}, nil
}

// Provide allows the provider to provide configurations to traefik
// using the given configuration channel.
func (provider *ECS) Provide(configurationChan chan<- types.ConfigMessage, pool *safe.Pool, constraints types.Constraints) error {

	provider.Constraints = append(provider.Constraints, constraints...)

	handleCanceled := func(ctx context.Context, err error) error {
		if ctx.Err() == context.Canceled || err == context.Canceled {
			return nil
		}
		return err
	}

	pool.Go(func(stop chan bool) {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			select {
			case <-stop:
				cancel()
			}
		}()

		operation := func() error {
			aws, err := provider.createClient()
			if err != nil {
				return err
			}

			configuration, err := provider.loadECSConfig(ctx, aws)
			if err != nil {
				return handleCanceled(ctx, err)
			}

			configurationChan <- types.ConfigMessage{
				ProviderName:  "ecs",
				Configuration: configuration,
			}

			if provider.Watch {
				reload := time.NewTicker(time.Second * time.Duration(provider.RefreshSeconds))
				defer reload.Stop()
				for {
					select {
					case <-reload.C:
						configuration, err := provider.loadECSConfig(ctx, aws)
						if err != nil {
							return handleCanceled(ctx, err)
						}

						configurationChan <- types.ConfigMessage{
							ProviderName:  "ecs",
							Configuration: configuration,
						}
					case <-ctx.Done():
						return handleCanceled(ctx, ctx.Err())
					}
				}
			}

			return nil
		}

		notify := func(err error, time time.Duration) {
			log.Errorf("ECS connection error %+v, retrying in %s", err, time)
		}
		err := backoff.RetryNotify(safe.OperationWithRecover(operation), job.NewBackOff(backoff.NewExponentialBackOff()), notify)
		if err != nil {
			log.Errorf("Cannot connect to ECS api %+v", err)
		}
	})

	return nil
}

func wrapAws(ctx context.Context, req *request.Request) error {
	req.HTTPRequest = req.HTTPRequest.WithContext(ctx)
	return req.Send()
}

func (provider *ECS) loadECSConfig(ctx context.Context, client *awsClient) (*types.Configuration, error) {
	var ecsFuncMap = template.FuncMap{
		"filterFrontends": provider.filterFrontends,
		"getFrontendRule": provider.getFrontendRule,
	}

	instances, err := provider.listInstances(ctx, client)
	if err != nil {
		return nil, err
	}

	instances = fun.Filter(provider.filterInstance, instances).([]ecsInstance)

	return provider.getConfiguration("templates/ecs.tmpl", ecsFuncMap, struct {
		Instances []ecsInstance
	}{
		instances,
	})
}

// Find all running ECS tasks in a cluster, also collect the task definitions (for docker labels)
// and the EC2 instance data
func (provider *ECS) listInstances(ctx context.Context, client *awsClient) ([]ecsInstance, error) {
	var taskArns []*string
	req, _ := client.ecs.ListTasksRequest(&ecs.ListTasksInput{
		Cluster:       &provider.Cluster,
		DesiredStatus: aws.String(ecs.DesiredStatusRunning),
	})

	for ; req != nil; req = req.NextPage() {
		if err := wrapAws(ctx, req); err != nil {
			return nil, err
		}

		taskArns = append(taskArns, req.Data.(*ecs.ListTasksOutput).TaskArns...)
	}

	req, taskResp := client.ecs.DescribeTasksRequest(&ecs.DescribeTasksInput{
		Tasks:   taskArns,
		Cluster: &provider.Cluster,
	})

	if err := wrapAws(ctx, req); err != nil {
		return nil, err
	}

	containerInstanceArns := make([]*string, 0)
	byContainerInstance := make(map[string]int)

	taskDefinitionArns := make([]*string, 0)
	byTaskDefinition := make(map[string]int)

	for _, task := range taskResp.Tasks {
		if _, found := byContainerInstance[*task.ContainerInstanceArn]; !found {
			byContainerInstance[*task.ContainerInstanceArn] = len(containerInstanceArns)
			containerInstanceArns = append(containerInstanceArns, task.ContainerInstanceArn)
		}
		if _, found := byTaskDefinition[*task.TaskDefinitionArn]; !found {
			byTaskDefinition[*task.TaskDefinitionArn] = len(taskDefinitionArns)
			taskDefinitionArns = append(taskDefinitionArns, task.TaskDefinitionArn)
		}
	}

	machines, err := provider.lookupEc2Instances(ctx, client, containerInstanceArns)
	if err != nil {
		return nil, err
	}

	taskDefinitions, err := provider.lookupTaskDefinitions(ctx, client, taskDefinitionArns)
	if err != nil {
		return nil, err
	}

	var instances []ecsInstance
	for _, task := range taskResp.Tasks {

		machineIdx := byContainerInstance[*task.ContainerInstanceArn]
		taskDefIdx := byTaskDefinition[*task.TaskDefinitionArn]

		for _, container := range task.Containers {

			taskDefinition := taskDefinitions[taskDefIdx]
			var containerDefinition *ecs.ContainerDefinition
			for _, def := range taskDefinition.ContainerDefinitions {
				if *container.Name == *def.Name {
					containerDefinition = def
					break
				}
			}

			instances = append(instances, ecsInstance{
				fmt.Sprintf("%s-%s", strings.Replace(*task.Group, ":", "-", 1), *container.Name),
				(*task.TaskArn)[len(*task.TaskArn)-12:],
				task,
				taskDefinition,
				container,
				containerDefinition,
				machines[machineIdx],
			})
		}
	}

	return instances, nil
}

func (provider *ECS) lookupEc2Instances(ctx context.Context, client *awsClient, containerArns []*string) ([]*ec2.Instance, error) {
	req, containerResp := client.ecs.DescribeContainerInstancesRequest(&ecs.DescribeContainerInstancesInput{
		ContainerInstances: containerArns,
		Cluster:            &provider.Cluster,
	})

	if err := wrapAws(ctx, req); err != nil {
		return nil, err
	}

	order := make(map[string]int)
	for i, arn := range containerArns {
		order[*arn] = i
	}

	instanceIds := make([]*string, len(containerArns))
	for i, container := range containerResp.ContainerInstances {
		order[*container.Ec2InstanceId] = order[*container.ContainerInstanceArn]
		instanceIds[i] = container.Ec2InstanceId
	}

	req, instancesResp := client.ec2.DescribeInstancesRequest(&ec2.DescribeInstancesInput{
		InstanceIds: instanceIds,
	})

	if err := wrapAws(ctx, req); err != nil {
		return nil, err
	}

	instances := make([]*ec2.Instance, len(containerArns))
	for _, r := range instancesResp.Reservations {
		instances[order[*r.Instances[0].InstanceId]] = r.Instances[0]
	}
	return instances, nil
}

func (provider *ECS) lookupTaskDefinitions(ctx context.Context, client *awsClient, taskDefArns []*string) ([]*ecs.TaskDefinition, error) {
	taskDefinitions := make([]*ecs.TaskDefinition, len(taskDefArns))
	for i, arn := range taskDefArns {

		req, resp := client.ecs.DescribeTaskDefinitionRequest(&ecs.DescribeTaskDefinitionInput{
			TaskDefinition: arn,
		})

		if err := wrapAws(ctx, req); err != nil {
			return nil, err
		}

		taskDefinitions[i] = resp.TaskDefinition
	}
	return taskDefinitions, nil
}

func (i ecsInstance) label(k string) string {
	if v, found := i.containerDefinition.DockerLabels[k]; found {
		return *v
	}
	return ""
}

func (provider *ECS) filterInstance(i ecsInstance) bool {
	if len(i.container.NetworkBindings) == 0 {
		log.Debugf("Filtering ecs instance without port %s (%s)", i.Name, i.ID)
		return false
	}

	label := i.label("traefik.enable")
	enabled := provider.ExposedByDefault && label != "false" || label == "true"
	if !enabled {
		log.Debugf("Filtering disabled ecs instance %s (%s) (traefik.enabled = '%s')", i.Name, i.ID, label)
		return false
	}

	return true
}

func (provider *ECS) filterFrontends(instances []ecsInstance) []ecsInstance {
	byName := make(map[string]bool)

	return fun.Filter(func(i ecsInstance) bool {
		if _, found := byName[i.Name]; !found {
			byName[i.Name] = true
			return true
		}

		return false
	}, instances).([]ecsInstance)
}

func (provider *ECS) getFrontendRule(i ecsInstance) string {
	if label := i.label("traefik.frontend.rule"); label != "" {
		return label
	}
	return "Host:" + strings.ToLower(strings.Replace(i.Name, "_", "-", -1)) + "." + provider.Domain
}

func (i ecsInstance) Protocol() string {
	if label := i.label("traefik.protocol"); label != "" {
		return label
	}
	return "http"
}

func (i ecsInstance) Host() string {
	return *i.machine.PrivateIpAddress
}

func (i ecsInstance) Port() string {
	return strconv.FormatInt(*i.container.NetworkBindings[0].HostPort, 10)
}

func (i ecsInstance) Weight() string {
	if label := i.label("traefik.weight"); label != "" {
		return label
	}
	return "0"
}

func (i ecsInstance) PassHostHeader() string {
	if label := i.label("traefik.frontend.passHostHeader"); label != "" {
		return label
	}
	return "true"
}

func (i ecsInstance) Priority() string {
	if label := i.label("traefik.frontend.priority"); label != "" {
		return label
	}
	return "0"
}

func (i ecsInstance) EntryPoints() []string {
	if label := i.label("traefik.frontend.entryPoints"); label != "" {
		return strings.Split(label, ",")
	}
	return []string{}
}
