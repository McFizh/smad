package main

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"slices"
	"smad/models"
)

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func readUsersAndGroups(config *models.AppConfig) {
	if config.Configuration.UserFile == "" || !fileExists(config.Configuration.UserFile) {
		log.Fatalln("'userFile' not set in config.json or file not found")
	}
	if config.Configuration.GroupFile == "" || !fileExists(config.Configuration.GroupFile) {
		log.Fatalln("'groupFile' not set in config.json or file not found")
	}

	fs1, err := os.Open(config.Configuration.UserFile)
	if err != nil {
		log.Fatalln(err)
	}
	defer fs1.Close()
	content1, _ := io.ReadAll(fs1)
	json.Unmarshal(content1, &config.Users)

	fs2, err := os.Open(config.Configuration.GroupFile)
	if err != nil {
		log.Fatalln(err)
	}
	defer fs2.Close()
	content2, _ := io.ReadAll(fs2)
	json.Unmarshal(content2, &config.Groups)
}

// Goes through user records and adds userPrincipalName attribute,
// also makes sure that group record contains only valid groups
func processUsers(users *[]models.User, groups *[]models.Group) {
	// Make sure all groups exist that user is ment to belong to
	for _, user := range *users {

		var newGroups []string
		for _, group := range user.Groups {
			if len(group) == 0 {
				continue
			}

			groupIdx := slices.IndexFunc(*groups, func(c models.Group) bool { return c.Cn == group })
			if groupIdx >= 0 {
				newGroups = append(newGroups, group)
			}
		}

		user.Attributes["userPrincipalName"] = user.Upn
		user.Attributes["name"] = user.Cn
		user.Groups = newGroups
	}
}

func readConfig() models.AppConfig {
	fs, err := os.Open("configs/config.json")
	if err != nil {
		if os.IsNotExist(err) {
			log.Fatalln("Missing config.json configuration file")
		}

		log.Fatalln(err)
	}
	defer fs.Close()

	content, _ := io.ReadAll(fs)
	var config models.AppConfig
	json.Unmarshal(content, &config.Configuration)

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

	// Finally read in users and groups
	readUsersAndGroups(&config)
	processUsers(&config.Users, &config.Groups)

	return config
}
