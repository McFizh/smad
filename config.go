package main

import (
	"encoding/json"
	"io"
	"log"
	"os"
)

type Configuration struct {
	UseSSL  bool
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

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func readConfig() AppConfig {
	fs, err := os.Open("config.json")
	if err != nil {
		if os.IsNotExist(err) {
			log.Fatalln("Missing config.json configuration file")
		}

		log.Fatalln(err)
	}
	defer fs.Close()

	content, _ := io.ReadAll(fs)
	var config AppConfig
	json.Unmarshal(content, &config)

	// Set default value, if port value is not set or invalid
	if config.Configuration.Port <= 0 {
		config.Configuration.Port = 389
	}

	// If crtfile and keyfile are set, then they must also exist
	config.Configuration.UseSSL = false
	if config.Configuration.CrtFile != "" && config.Configuration.KeyFile != "" {
		if !fileExists(config.Configuration.KeyFile) {
			log.Fatalln("'keyFile' set in config.json but file not found")
		}
		if !fileExists(config.Configuration.CrtFile) {
			log.Fatalln("'crtFile' set in config.json but file not found")
		}

		config.Configuration.UseSSL = true
	}

	return config
}
