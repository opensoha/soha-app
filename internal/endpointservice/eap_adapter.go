package endpointservice

type EAPAdapter struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Medium           string `json:"medium"`
	MACAddress       string `json:"macAddress"`
	EthernetPosition int    `json:"ethernetPosition,omitempty"`
	Enabled          bool   `json:"enabled"`
	LinkUp           bool   `json:"linkUp"`
}
