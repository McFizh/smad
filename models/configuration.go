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

type LdapElement struct {
	Cn                 string
	Attributes         map[string]string
	MemberOf           []string
	ObjectClass        []string
	UserAccountControl int
}

type User struct {
	Cn                  string            `json:"cn"`
	Upn                 string            `json:"upn"`
	Password            string            `json:"password"`
	PasswordNeverExpire bool              `json:"passwordNeverExpire"`
	Disabled            bool              `json:"accountDisabled"`
	Attributes          map[string]string `json:"attributes"`
	Groups              []string          `json:"groups"`
	UserAccountControl  int
}

type Group struct {
	Cn string `json:"cn"`
}

type AppConfig struct {
	Configuration Configuration
	Users         []User
	Groups        []Group
}
