package ldap

import ber "github.com/go-asn1-ber/asn1-ber"

func createResponsePacket(msgNum uint8) *ber.Packet {
	rsp := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	msgNumPacket := ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgNum, "")
	rsp.AppendChild(msgNumPacket)
	return rsp
}
