package netlink

import (
	"bytes"
	"encoding/binary"
	"github.com/vishvananda/netlink/nl"
	"log"
	"syscall"
)

const (
	fart = 4
)

const (
	IFLA_BRIDGE_FLAGS = iota
	IFLA_BRIDGE_MODE
	IFLA_BRIDGE_VLAN_INFO
	IFLA_BRIDGE_VLAN_TUNNEL_INFO
	IFLA_BRIDGE_MAX
)

// bridge-vlan flags
const (
	BRIDGE_VLAN_INFO_MASTER      = 0x1
	BRIDGE_VLAN_INFO_PVID        = 0x2
	BRIDGE_VLAN_INFO_UNTAGGED    = 0x4
	BRIDGE_VLAN_INFO_RANGE_BEGIN = 0x8
	BRIDGE_VLAN_INFO_RANGE_END   = 0x10
	BRIDGE_VLAN_INFO_BRENTRY     = 0x20
)

// bridge flags
const (
	BRIDGE_FLAGS_MASTER = 1
	BRIDGE_FLAGS_SELF   = 2
)

const (
	RTEXT_FILTER_BRVLAN = 2
)

type BridgeVlanInfo struct {
	Flags uint16
	Vid   uint16
}

type BridgeInfo struct {
	Index int
	Vlans []*VlanInfo
}

type VlanInfo struct {
	Vid                                                   uint16
	Master, Pvid, Untagged, RangeBegin, RangeEnd, Brentry bool
}

func GetBridgeInfo() ([]*BridgeInfo, error) {
	return pkgHandle.GetBridgeInfo()
}

func attributeBuffer(data_len, kind int, data interface{}) []byte {
	length := data_len + 4 //header is 4 bytes
	nra := &syscall.RtAttr{Len: uint16(length), Type: uint16(kind)}
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, nra.Len)
	binary.Write(buf, binary.LittleEndian, nra.Type)
	if data != nil {
		binary.Write(buf, binary.LittleEndian, data)
	}
	if buf.Len()%4 != 0 {
		pad := 4 - buf.Len()%4
		binary.Write(buf, binary.LittleEndian, make([]byte, pad))
	}
	return buf.Bytes()
}

func (h *Handle) bridgeMsg(
	proto, flags int, ifi *nl.IfInfomsg) *nl.NetlinkRequest {

	// build the base netlink request
	req := h.newNetlinkRequest(
		proto,
		flags,
	)

	req.AddData(ifi)

	return req
}

func BridgeVlanAdd(
	vid uint, dev_index int, bridge_flags, vinfo_flags uint) error {

	return pkgHandle.bridgeVlanModlink(
		syscall.RTM_SETLINK, vid, dev_index, bridge_flags, vinfo_flags)

}

func BridgeVlanDel(
	vid uint, dev_index int, bridge_flags, vinfo_flags uint) error {

	return pkgHandle.bridgeVlanModlink(
		syscall.RTM_DELLINK, vid, dev_index, bridge_flags, vinfo_flags)

}

func (h *Handle) bridgeVlanModlink(
	cmd, vid uint, dev_index int, bridge_flags, vinfo_flags uint) error {

	vinfo := &BridgeVlanInfo{
		Vid:   uint16(vid),
		Flags: uint16(vinfo_flags),
	}

	//restrict the netlink set request to the bridge in question
	ifi := nl.NewIfInfomsg(syscall.AF_BRIDGE)
	ifi.Index = int32(dev_index)

	//build the netlink request
	req := h.bridgeMsg(
		int(cmd),
		syscall.NLM_F_REQUEST|syscall.NLM_F_ACK,
		ifi,
	)

	//add the nest attribute
	//nest length
	nest_len := 8 //sizeof nest header + vlan-info attribute

	if bridge_flags != 0 {
		nest_len += 8 //sizeof bridge flags attribute (plus 2 bytes of padding)
	}

	nest := attributeBuffer(nest_len, nl.IFLA_AF_SPEC, nil)
	req.AddRawData(nest)

	//add the bridge flags
	if bridge_flags != 0 {
		br_flags := attributeBuffer(4, IFLA_BRIDGE_FLAGS, uint16(bridge_flags))
		req.AddRawData(br_flags)
	}

	//add the vlan info
	vl_info := attributeBuffer(4, IFLA_BRIDGE_VLAN_INFO, vinfo)
	req.AddRawData(vl_info)

	//call down into netlink
	soctype := int(syscall.NETLINK_ROUTE)
	restype := uint16(0)
	log.Printf("sending netlink message")
	_, err := req.Execute(soctype, restype)
	if err != nil {
		return err
	} else {
		log.Printf("netlink message sent")
	}

	return nil

}

func (h *Handle) GetBridgeInfo() ([]*BridgeInfo, error) {

	//craft our netlink request to get all the vlan info from all the bridges
	req := h.bridgeMsg(
		syscall.RTM_GETLINK,
		syscall.NLM_F_DUMP|syscall.NLM_F_REQUEST,
		nl.NewIfInfomsg(syscall.AF_BRIDGE),
	)
	vlan_xt := attributeBuffer(4, nl.IFLA_EXT_MASK, uint32(RTEXT_FILTER_BRVLAN))
	req.AddRawData(vlan_xt)

	//call down into netlink
	msgs, err := req.Execute(syscall.NETLINK_ROUTE, syscall.RTM_NEWLINK)
	if err != nil {
		return nil, err
	}

	//build the result from the netlink response
	var result []*BridgeInfo
	for _, m := range msgs {
		b, err := BridgeDeserialize(nil, m)
		if err != nil {
			return nil, err
		}
		result = append(result, b)
	}

	return result, nil
}

func BridgeDeserialize(hdr *syscall.NlMsghdr, m []byte) (*BridgeInfo, error) {

	msg := nl.DeserializeIfInfomsg(m)
	attrs, err := nl.ParseRouteAttr(m[msg.Len():])
	if err != nil {
		return nil, err
	}
	if msg.Family != syscall.AF_BRIDGE {
		return nil, nil
	}

	bi := &BridgeInfo{Index: int(msg.Index)}

	for _, attr := range attrs {
		switch attr.Attr.Type {
		case nl.IFLA_AF_SPEC:
			infos, err := nl.ParseRouteAttr(attr.Value)
			if err != nil {
				return nil, err
			}
			for _, info := range infos {
				switch info.Attr.Type {
				case IFLA_BRIDGE_VLAN_INFO:
					vl := &VlanInfo{}
					r := bytes.NewReader(info.Value)
					var flags uint16
					binary.Read(r, binary.LittleEndian, &flags)
					binary.Read(r, binary.LittleEndian, &vl.Vid)

					vl.Master = flags&BRIDGE_VLAN_INFO_MASTER != 0
					vl.Pvid = flags&BRIDGE_VLAN_INFO_PVID != 0
					vl.Untagged = flags&BRIDGE_VLAN_INFO_UNTAGGED != 0
					vl.RangeBegin = flags&BRIDGE_VLAN_INFO_RANGE_BEGIN != 0
					vl.RangeEnd = flags&BRIDGE_VLAN_INFO_RANGE_END != 0
					vl.Brentry = flags&BRIDGE_VLAN_INFO_BRENTRY != 0
					bi.Vlans = append(bi.Vlans, vl)
				}
			}
		}
	}
	return bi, nil
}
