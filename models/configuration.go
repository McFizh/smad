package models

type Configuration struct {
	UseSSL    bool
	Port      int    `json:"port"`
	CrtFile   string `json:"crtFile"`
	KeyFile   string `json:"keyFile"`
	UserFile  string `json:"userFile"`
	GroupFile string `json:"groupFile"`
	Domain    string `json:"domain"`
}

type User struct {
	Upn        string            `json:"upn"`
	Password   string            `json:"password"`
	Attributes map[string]string `json:"attributes"`
	Groups     []string          `json:"groups"`
}

type Group struct {
	Name string `json:"name"`
}

type AppConfig struct {
	Configuration Configuration
	Users         []User
	Groups        []Group
}
