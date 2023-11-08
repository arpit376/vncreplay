package main

import (
	"flag"
	"log"
	"os"
	"time"
	"fmt"
	"github.com/thijzert/vncreplay/rfb"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)
var expectedAck uint32

func processPacket(packet gopacket.Packet) {
	// Replace this with your own packet processing logic
	fmt.Println(packet)
}

func main() {
	var inFile, outFile string
	var embedAssets bool
	flag.StringVar(&inFile, "i", "", "Input file")
	flag.StringVar(&outFile, "o", "replay.html", "Output file")
	flag.BoolVar(&embedAssets, "embedAssets", true, "Embed static assets in the output HTML")
	flag.Parse()
	fmt.Print("Input selected") //added for debug
	if inFile == "" {
		if len(flag.Args()) > 0 {
			inFile = flag.Args()[0]
		} else {
			log.Fatalf("Usage: %s [-o OUTFILE] INFILE", os.Args[0])
		}
	}

	out, err := os.Create(outFile)
	if err != nil {
		log.Fatal(err)
	}
	replay, err := rfb.New(out)
	if err != nil {
		log.Fatal(err)
		fmt.Print("Fatal Error ref.New") //debug
	}
	replay.EmbedAssets = embedAssets
	defer replay.Close()

	var handle *pcap.Handle

	// Open pcap file
	handle, err = pcap.OpenOffline(inFile)
	if err != nil {
		log.Fatal(err)
		fmt.Print("Failed to open file") //debug
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Map to store out-of-order packets
	outOfOrderPackets := make(map[uint32][]gopacket.Packet)

	var serverPort, sourcePort layers.TCPPort = 0, 0
	var serverSeq, clientSeq uint32 = 0, 0
	var t0 time.Time
	var packetCount uint32 = 0

	for packet := range packetSource.Packets() {
		packetCount++
		// Get the TCP layer from this packet
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			// Get actual TCP data from this layer
			tcp, _ := tcpLayer.(*layers.TCP)
			seq := tcp.Seq  //for sequence
			ack := tcp.Ack  //for acknowledge
			//fmt.Print("TCP Data received") //Debug
			if ack == expectedAck {
				processPacket(packet)
				expectedAck = seq + uint32(len(tcp.Payload))
			} else {
				// Store out-of-order packets
				outOfOrderPackets[ack] = append(outOfOrderPackets[ack], packet)
			}
			for {
				nextPackets, exists := outOfOrderPackets[expectedAck]
				if !exists {
					break
				}

				// Process the out-of-order packets in order
				for _, nextPacket := range nextPackets {
					processPacket(nextPacket)
				}

				delete(outOfOrderPackets, expectedAck)
				expectedAck += uint32(len(nextPackets[len(nextPackets)-1].Layer(layers.LayerTypeTCP).(*layers.TCP).Payload))
			}
			meta := packet.Metadata()
			if serverPort == 0 && sourcePort == 0 {
				// Assume the first packet is the first SYN
				serverPort, sourcePort = tcp.DstPort, tcp.SrcPort
				t0 = meta.Timestamp
				fmt.Print("Port Data received\n") //Debug
			}

			if tcp.SYN {
				if tcp.SrcPort == serverPort {
					serverSeq = tcp.Seq + 1
				} else if tcp.SrcPort == sourcePort {
					clientSeq = tcp.Seq + 1
				}
				fmt.Print("SYN received\n") //Debug
			}

			if len(tcp.Payload) == 0 {
				continue
			}

			tpacket := meta.Timestamp.Sub(t0)

			err = nil
			if tcp.SrcPort == serverPort {
				err = replay.ServerBytes(tpacket, int(tcp.Seq-serverSeq), tcp.Payload)
				fmt.Printf("Source Server Port %v\n", serverSeq)
			} else if tcp.SrcPort == sourcePort {
				err = replay.ClientBytes(tpacket, int(tcp.Seq-clientSeq), tcp.Payload)
				fmt.Printf("Source Client Port %v\n", clientSeq)
			} else {
				log.Printf("Ignoring extra traffic " )
			}
			if err != nil {
				fmt.Printf("Error - Fatal  packet %d error is %v\n", packetCount, err)
				log.Fatal(err)
			}
		}
	}
}
