package ldap

import (
	"net"
	"smad/models"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func HandleDeleteRequest(conn net.Conn, p *ber.Packet, msgNum uint8, bindSuccessful bool, config *models.AppConfig) {
	// Instead of getting stuck due to empty mock implementation, return not supported packet
	rsp := createResponsePacket(msgNum)
	delRspPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0x0b, nil, "")
	delRspPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 53, ""))
	delRspPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	delRspPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "Delete not supported", ""))
	rsp.AppendChild(delRspPacket)
	conn.Write(rsp.Bytes())
}
