// ----------------------------
// Get All Routers
// ----------------------------
export function getAllRoutersRequest (state) {
  state.allRouters.loading = true
}

export function getAllRoutersSuccess (state, data) {
  const { body, query = '', status = '', page } = data
  const currentState = state.allRouters

  const isSameContext = currentState.currentQuery === query && currentState.currentStatus === status

  state.allRouters = {
    ...state.allRouters,
    items: [
      ...(isSameContext && currentState.items && page !== 1 ? currentState.items : []),
      ...(body.data || [])
    ],
    currentPage: page,
    total: body.total,
    loading: false,
    currentQuery: query,
    currentStatus: status
  }
}

export function getAllRoutersFailure (state, error) {
  state.allRouters = {
    ...state.allRouters,
    loading: false,
    error,
    endReached: error.message.includes('invalid request: page:')
  }
}

export function getAllRoutersClear (state) {
  state.allRouters = {}
}

// ----------------------------
// Get Router By Name
// ----------------------------
export function getRouterByNameRequest (state) {
  state.routerByName.loading = true
}

export function getRouterByNameSuccess (state, body) {
  state.routerByName = { item: body, loading: false }
}

export function getRouterByNameFailure (state, error) {
  state.routerByName = { error }
}

export function getRouterByNameClear (state) {
  state.routerByName = {}
}

// ----------------------------
// Get All Services
// ----------------------------
export function getAllServicesRequest (state) {
  state.allServices.loading = true
}

export function getAllServicesSuccess (state, data) {
  const { body, query = '', status = '', page } = data
  const currentState = state.allServices

  const isSameContext = currentState.currentQuery === query && currentState.currentStatus === status

  state.allServices = {
    ...state.allServices,
    items: [
      ...(isSameContext && currentState.items && page !== 1 ? currentState.items : []),
      ...(body.data || [])
    ],
    currentPage: page,
    total: body.total,
    loading: false,
    currentQuery: query,
    currentStatus: status
  }
}

export function getAllServicesFailure (state, error) {
  state.allServices = {
    ...state.allServices,
    loading: false,
    error,
    endReached: error.message.includes('invalid request: page:')
  }
}

export function getAllServicesClear (state) {
  state.allServices = {}
}

// ----------------------------
// Get Service By Name
// ----------------------------
export function getServiceByNameRequest (state) {
  state.serviceByName.loading = true
}

export function getServiceByNameSuccess (state, body) {
  state.serviceByName = { item: body, loading: false }
}

export function getServiceByNameFailure (state, error) {
  state.serviceByName = { error }
}

export function getServiceByNameClear (state) {
  state.serviceByName = {}
}

// ----------------------------
// Get All Middlewares
// ----------------------------
export function getAllMiddlewaresRequest (state) {
  state.allMiddlewares.loading = true
}

export function getAllMiddlewaresSuccess (state, data) {
  const { body, query = '', status = '', page } = data
  const currentState = state.allMiddlewares

  const isSameContext = currentState.currentQuery === query && currentState.currentStatus === status

  state.allMiddlewares = {
    ...state.allMiddlewares,
    items: [
      ...(isSameContext && currentState.items && page !== 1 ? currentState.items : []),
      ...(body.data || [])
    ],
    currentPage: page,
    total: body.total,
    loading: false,
    currentQuery: query,
    currentStatus: status
  }
}

export function getAllMiddlewaresFailure (state, error) {
  state.allMiddlewares = {
    ...state.allMiddlewares,
    loading: false,
    error,
    endReached: error.message.includes('invalid request: page:')
  }
}

export function getAllMiddlewaresClear (state) {
  state.allMiddlewares = {}
}

// ----------------------------
// Get Middleware By Name
// ----------------------------
export function getMiddlewareByNameRequest (state) {
  state.middlewareByName.loading = true
}

export function getMiddlewareByNameSuccess (state, body) {
  state.middlewareByName = { item: body, loading: false }
}

export function getMiddlewareByNameFailure (state, error) {
  state.middlewareByName = { error }
}

export function getMiddlewareByNameClear (state) {
  state.middlewareByName = {}
}
