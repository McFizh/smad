package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type Configuration struct {
	Port    int    `json:"port"`
	CrtFile string `json:"crtFile"`
	KeyFile string `json:"keyFile"`
}

type User struct {
	Upn      string `json:"upn"`
	Password string `json:"password"`
}

type AppConfig struct {
	Configuration Configuration `json:"configuration"`
	Users         []User        `json:"users"`
}

func readConfig() AppConfig {
	fs, err := os.Open("config.json")
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("Missing config.json configuration file")
		} else {
			fmt.Println(err)
		}
		os.Exit(1)
	}
	defer fs.Close()

	content, _ := io.ReadAll(fs)
	var config AppConfig
	json.Unmarshal(content, &config)

	// Set default value, if port value is not set or invalid
	if config.Configuration.Port <= 0 {
		config.Configuration.Port = 389
	}

	return config
}
