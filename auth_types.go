package zensframework

// CheckRolesRequest representa uma requisição para verificar roles
type CheckRolesRequest struct {
	Roles []string `json:"roles" binding:"required"`
}

// CheckPermissionsRequest representa uma requisição para verificar permissões
type CheckPermissionsRequest struct {
	Permissions []string `json:"permissions" binding:"required"`
}

// CheckResponse representa a resposta de uma verificação de autorização
type CheckResponse struct {
	Allowed bool   `json:"allowed"`
	Message string `json:"message,omitempty"`
}