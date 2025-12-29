package ldap

import (
	"net"
	"smad/models"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func HandleDeleteRequest(conn net.Conn, p *ber.Packet, msgNum uint8, bindSuccessful bool, config models.AppConfig) {
}
