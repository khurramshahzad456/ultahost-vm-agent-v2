package models

type CommandRequest struct {
	Command string `json:"command" binding:"required"`
	Hash    string `json:"hash" binding:"required"`
}

type CommandResponse struct {
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}
