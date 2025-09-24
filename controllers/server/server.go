package server

import httpServices "dms-accounting/httpServices/sso"

type SSOController struct {
	httpService *httpServices.SSOClient
}

func NewSSOController(service *httpServices.SSOClient) *SSOController {
	return &SSOController{httpService: service}
}
