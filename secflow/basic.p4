#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv4_options_t {
        //Need fields
        bit<1> copyFlag;
        bit<2> optClass;
        bit<5> option;
        bit<8> optionLength;

        //Option data---used as telemetry
        ip4Addr_t orignal_srcIP;
        ip4Addr_t orignal_dstIP;
        bit<16> spkts; //Source-Dst packets
        bit<16> dpkts; //Dst-Source packets
        bit<16> attack_packet; //Number of packets detected as attack
}

struct metadata {
    /* empty */
    bit<1> isSwitch;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    ipv4_options_t ipv4_option;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    apply {}
           //if(hdr.ipv4.isValid() && meta.isSwitch ==1){
		// hdr.ipv4_option.spkts = (bit<16>)standard_metadata.deq_timedelta;
    //}}
}

/*************************************************************************
****************  I N  R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    apply {  
	      if(hdr.ipv4.isValid()){
	        if(hdr.ipv4.dstAddr!=0x0A000303){
		hdr.ipv4.ttl = hdr.ipv4.ttl + 1;
                hdr.ipv4_option.setValid();
                hdr.ipv4_option.copyFlag =0;
                hdr.ipv4_option.optClass =0;
                hdr.ipv4_option.option =31;
                hdr.ipv4_option.optionLength=8; //Total number of bytes
                hdr.ipv4_option.orignal_srcIP=hdr.ipv4.dstAddr;
                hdr.ipv4_option.orignal_dstIP=hdr.ipv4.srcAddr;
                hdr.ipv4_option.spkts= (bit<16>) standard_metadata.deq_timedelta; 
                //hdr.ipv4_option.spkts = 0;
                hdr.ipv4_option.dpkts= 0;
                hdr.ipv4_option.attack_packet= 0;

                //Change address to sdn controller's
                hdr.ipv4.srcAddr = 0x0a000101;

                hdr.ipv4.dstAddr =  0x0A000303;
                //Change length field of ipv4
                hdr.ipv4.ihl = hdr.ipv4.ihl + 4; //(4 times 32 bits)
                hdr.ipv4.totalLen =  hdr.ipv4.totalLen + 16;//16 bytes of option
		meta.isSwitch=1;
		}
                //hdr.packet_payload.setInvalid();
		ipv4_lpm.apply();   
	}}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
	packet.emit(hdr.ipv4_option);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
