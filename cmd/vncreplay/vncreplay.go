package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	var inFile, outFile string
	flag.StringVar(&inFile, "i", "", "Input file")
	flag.StringVar(&outFile, "o", "replay.html", "Output file")
	flag.Parse()

	if inFile == "" {
		if len(flag.Args()) > 0 {
			inFile = flag.Args()[0]
		} else {
			log.Fatalf("Usage: replay [-o OUTFILE] INFILE")
		}
	}

	out, err := os.Create(outFile)
	if err != nil {
		log.Fatal(err)
	}
	rfb := NewRFB(out)
	defer rfb.Close()

	var handle *pcap.Handle

	// Open pcap file
	handle, err = pcap.OpenOffline(inFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var serverPort, sourcePort layers.TCPPort = 0, 0
	var t0 time.Time

	for packet := range packetSource.Packets() {
		// Get the TCP layer from this packet
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			// Get actual TCP data from this layer
			tcp, _ := tcpLayer.(*layers.TCP)

			meta := packet.Metadata()
			if serverPort == 0 && sourcePort == 0 {
				// Assume the first packet is the first SYN
				serverPort, sourcePort = tcp.DstPort, tcp.SrcPort
				t0 = meta.Timestamp
			}

			if len(tcp.Payload) == 0 {
				continue
			}

			tpacket := meta.Timestamp.Sub(t0)

			err = nil
			if tcp.SrcPort == serverPort {
				err = rfb.ServerBytes(tpacket, tcp.Seq, tcp.Payload)
			} else if tcp.SrcPort == sourcePort {
				err = rfb.ClientBytes(tpacket, tcp.Seq, tcp.Payload)
			} else {
				log.Printf("Ignoring extra traffic")
			}
			if err != nil {
				log.Fatal(err)
			}
		}
	}
}

type RFB struct {
	htmlOut      io.WriteCloser
	clientBuffer []byte
	serverBuffer []byte
	clientOffset int
	serverOffset int
	width        int
	height       int
	pixelFormat  PixelFormat
	name         string
}

func NewRFB(out io.WriteCloser) *RFB {
	var rfb = &RFB{
		htmlOut:      out,
		clientBuffer: make([]byte, 0, 2000),
		serverBuffer: make([]byte, 0, 2000),
		clientOffset: 0,
		serverOffset: 0,
	}

	rfb.htmlOut.Write([]byte(`<!DOCTYPE html><html><body>`))

	return rfb
}

func (rfb *RFB) ClientBytes(t time.Duration, offset uint32, buf []byte) error {
	rfb.clientBuffer = append(rfb.clientBuffer, buf...)
	return nil
}

func (rfb *RFB) ServerBytes(t time.Duration, offset uint32, buf []byte) error {
	rfb.serverBuffer = append(rfb.serverBuffer, buf...)
	return nil
}

func (rfb *RFB) Close() error {
	if err := rfb.consumeHandshake(); err != nil {
		fmt.Fprintf(rfb.htmlOut, "<h2>error: %s</h2>", err)
		return err
	}

	fmt.Fprintf(rfb.htmlOut, `<h3>Client events</h3>`)
	if err := rfb.readClientBytes(); err != nil {
		fmt.Fprintf(rfb.htmlOut, "<h2>error: %s</h2>", err)
		return err
	}

	fmt.Fprintf(rfb.htmlOut, `<h3>Server events</h3>`)
	if err := rfb.readServerBytes(); err != nil {
		fmt.Fprintf(rfb.htmlOut, "<h2>error: %s</h2>", err)
		return err
	}

	fmt.Fprintf(rfb.htmlOut, `</body></html>`)
	return rfb.htmlOut.Close()
}

func (rfb *RFB) consumeHandshake() error {
	// Server version
	_ = rfb.nextS(12)

	// Client version
	_ = rfb.nextC(12)

	// Server security types
	nSecurity := rInt(rfb.nextS(1))
	_ = rfb.nextS(1 * nSecurity)

	// Client security choice
	sec := rInt(rfb.nextC(1))

	if sec == 2 {
		// VNC authentication
		_ = rfb.nextS(16)
		_ = rfb.nextC(16)
	} else {
		return fmt.Errorf("authentication type %d not implemented", sec)
	}

	// Server init
	securityResult := rInt(rfb.nextS(4))
	if securityResult != 0 {
		return fmt.Errorf("handshake failed: authentication failed: error %d", securityResult)
	}

	// Client init
	cInit := rfb.nextC(1)
	if len(cInit) != 1 {
		return fmt.Errorf("handshake failed: client rejected")
	}

	// Server init
	sInit := rfb.nextS(24)
	if len(sInit) != 24 {
		return fmt.Errorf("handshake failed: server rejected")
	}
	rfb.width = rInt(sInit[0:2])
	rfb.height = rInt(sInit[2:4])
	rfb.pixelFormat = ParsePixelFormat(sInit[4:20])
	fmt.Fprintf(rfb.htmlOut, "<div>Remote display %dx%d, %s</div>\n", rfb.width, rfb.height, rfb.pixelFormat)
	nlen := rInt(sInit[20:24])
	if nlen > 0 {
		rfb.name = string(rfb.nextS(nlen))
		fmt.Fprintf(rfb.htmlOut, "<div>Server name: %s</div>\n", rfb.name)
	}

	return nil
}

func (rfb *RFB) nextS(l int) []byte {
	start := rfb.serverOffset
	if (start + l) > len(rfb.serverBuffer) {
		l = len(rfb.serverBuffer) - rfb.serverOffset
	}

	rfb.serverOffset += l
	return rfb.serverBuffer[start : start+l]
}

func (rfb *RFB) nextC(l int) []byte {
	start := rfb.clientOffset
	if (start + l) > len(rfb.clientBuffer) {
		l = len(rfb.clientBuffer) - rfb.clientOffset
	}

	rfb.clientOffset += l
	return rfb.clientBuffer[start : start+l]
}

func (rfb *RFB) readClientBytes() error {
	for len(rfb.clientBuffer) > rfb.clientOffset {
		messageType := rfb.clientBuffer[rfb.clientOffset]
		if messageType == 0 {
			buf := rfb.nextC(20)
			rfb.pixelFormat = ParsePixelFormat(buf[4:20])
			fmt.Fprintf(rfb.htmlOut, "<div>Pixel format set to: %s</div>\n", rfb.pixelFormat)
		} else if messageType == 2 {
			fmt.Fprintf(rfb.htmlOut, "<div class=\"-todo\">TODO: SetEncodings</div>\n")
			_ = rfb.nextC(2)
			nEncs := rInt(rfb.nextC(2))
			_ = rfb.nextC(4 * nEncs)
		} else if messageType == 3 {
			buf := rfb.nextC(10)
			fmt.Fprintf(rfb.htmlOut, "<div>Framebuffer Update Request for a %dx%dpx area at %dx%d</div>\n", rInt(buf[2:4]), rInt(buf[4:6]), rInt(buf[6:8]), rInt(buf[8:10]))
		} else if messageType == 4 {
			buf := rfb.nextC(8)
			key := rInt(buf[4:8])
			if rInt(buf[1:2]) == 1 {
				fmt.Fprintf(rfb.htmlOut, "<div>Press key <tt>%c</tt> (0x%2x)</div>\n", key, key)
			} else {
				fmt.Fprintf(rfb.htmlOut, "<div>release key <tt>%c</tt> (0x%2x)</div>\n", key, key)
			}
		} else if messageType == 5 {
			buf := rfb.nextC(6)
			bm := rInt(buf[1:2])
			x := rInt(buf[2:4])
			y := rInt(buf[4:6])
			fmt.Fprintf(rfb.htmlOut, "<div class=\"-todo\">Move pointer to %d,%d with buttons %x</div>\n", x, y, bm)
		} else if messageType == 6 {
			fmt.Fprintf(rfb.htmlOut, "<div class=\"-todo\">TODO: ClientCutText</div>\n")
			rfb.nextC(len(rfb.clientBuffer))
		} else {
			fmt.Fprintf(rfb.htmlOut, "<div class=\"-error\">Unknown client packet type %d - ignoring all %d bytes</div>\n", messageType, len(rfb.clientBuffer))
			rfb.nextC(len(rfb.clientBuffer))
		}
	}

	return nil
}

func (rfb *RFB) readServerBytes() error {
	for len(rfb.serverBuffer) > rfb.serverOffset {
		messageType := rfb.serverBuffer[rfb.serverOffset]
		offset := len(rfb.serverBuffer[rfb.serverOffset:])
		if messageType == 0 {
			offset = rfb.decodeFrameBufferUpdate()
		} else if messageType == 1 {
			fmt.Fprintf(rfb.htmlOut, "<div class=\"-todo\">TODO: SetColourMapEntries</div>\n")
		} else if messageType == 2 {
			fmt.Fprintf(rfb.htmlOut, "<div class=\"-todo\">TODO: Bell</div>\n")
		} else if messageType == 3 {
			fmt.Fprintf(rfb.htmlOut, "<div class=\"-todo\">TODO: ServerCutText</div>\n")
		} else {
			fmt.Fprintf(rfb.htmlOut, "<div class=\"-error\">Unknown server packet type %d at offset %8x - ignoring all %d bytes</div>\n", messageType, rfb.serverOffset, len(rfb.serverBuffer[rfb.serverOffset:]))
		}
		if offset > len(rfb.serverBuffer[rfb.serverOffset:]) {
			offset = len(rfb.serverBuffer[rfb.serverOffset:])
		}
		log.Printf("Server packet of type %d consumed at index %08x len %d - next packet at %08x", messageType, rfb.serverOffset, offset, rfb.serverOffset+offset)
		rfb.serverOffset += offset
	}

	return nil
}

func (rfb *RFB) decodeFrameBufferUpdate() int {
	targetImage := image.NewRGBA(image.Rect(0, 0, rfb.width, rfb.height))

	nRects := rInt(rfb.serverBuffer[rfb.serverOffset+2 : rfb.serverOffset+4])
	rectsAdded := 0
	// log.Printf("Number of rects: %d", nRects)

	offset := 4
	for i := 0; i < nRects; i++ {
		n, img, enctype := rfb.pixelFormat.nextRect(rfb.serverBuffer[rfb.serverOffset+offset:])
		offset += n

		if enctype == -239 {
			rfb.handleCursorUpdate(img)
		} else if img != nil {
			b := img.Bounds()
			draw.Draw(targetImage, b, img, b.Min, draw.Over)
			rectsAdded++
		}
	}

	if rectsAdded > 0 {
		rfb.htmlOut.Write([]byte(`<div>framebuffer update<br /><img src="data:image/png;base64,`))
		png.Encode(base64.NewEncoder(base64.StdEncoding, rfb.htmlOut), targetImage)
		rfb.htmlOut.Write([]byte(`" /></div>`))
	}

	return offset
}

func (rfb *RFB) handleCursorUpdate(img image.Image) {
	if img.Bounds().Dx() > 0 && img.Bounds().Dy() > 0 {
		min := img.Bounds().Min
		fmt.Fprintf(rfb.htmlOut, `<div>Draw cursor like this: <img data-x="%d" data-y="%d" src="data:image/png;base64,`, min.X, min.Y)
		png.Encode(base64.NewEncoder(base64.StdEncoding, rfb.htmlOut), img)
		fmt.Fprintf(rfb.htmlOut, `" /></div>`)
	} else {
		fmt.Fprintf(rfb.htmlOut, `<div>Use the default cursor from here.</div>`)
	}
}

func (ppf PixelFormat) nextRect(buf []byte) (bytesRead int, img image.Image, enctype int32) {
	x := rInt(buf[0:2])
	y := rInt(buf[2:4])
	w := rInt(buf[4:6])
	h := rInt(buf[6:8])
	enctype = int32(uint32(rInt(buf[8:12])))
	// log.Printf("next rect is a %dx%d rectangle at position %d,%d", w, h, x, y)
	// log.Printf("encoding type: %02x (%d)", enctype, enctype)

	rv := image.NewRGBA(image.Rect(x, y, x+w, y+h))

	if enctype == 0 || enctype == -239 {
		// Raw encoding

		offset := 12
		rectEnd := 12 + h*w*ppf.BytesPerPixel()
		bitmaskOffset := 0
		if enctype == -239 {
			lineLength := (w + 7) / 8
			bitmaskOffset = h * lineLength
		}
		for j := 0; j < h; j++ {
			for i := 0; i < w; i++ {
				if offset >= len(buf) {
					// log.Printf("Warning: image truncated")
					return offset, rv, enctype
				}

				n, c := ppf.ReadPixel(buf[offset:])
				offset += n

				if enctype == -239 {
					// The cursor update pseudoformat also consists of a bitmask after
					// the pixel colours, corresponding to the alpha value of each pixel.

					lineLength := (w + 7) / 8
					aByte := j*lineLength + i/8
					aBit := i & 0x7
					if len(buf) > rectEnd+aByte {
						if (buf[rectEnd+aByte]<<aBit)&0x80 == 0 {
							c.A = 0
						}
					}
				}

				rv.Set(x+i, y+j, c)
			}
		}

		return offset + bitmaskOffset, rv, enctype
	} else {
		log.Printf("Unknown encoding type - ignoring whole buffer")
		return len(buf), nil, enctype
	}

	return 12, nil, 0
}

func rInt(b []byte) int {
	var rv int = 0
	for _, c := range b {
		rv = rv<<8 | int(c)
	}
	return rv
}

type PixelFormat struct {
	Bits       int
	Depth      int
	BigEndian  bool
	TrueColour bool
	RedMax     uint
	GreenMax   uint
	BlueMax    uint
	RedShift   uint
	GreenShift uint
	BlueShift  uint
}

func ParsePixelFormat(buf []byte) PixelFormat {
	var rv PixelFormat
	rv.Bits = rInt(buf[0:1])
	rv.Depth = rInt(buf[1:2])
	rv.BigEndian = rInt(buf[2:3]) > 0
	rv.TrueColour = rInt(buf[3:4]) > 0
	rv.RedMax = uint(rInt(buf[4:6]))
	rv.GreenMax = uint(rInt(buf[6:8]))
	rv.BlueMax = uint(rInt(buf[8:10]))
	rv.RedShift = uint(rInt(buf[10:11]))
	rv.GreenShift = uint(rInt(buf[11:12]))
	rv.BlueShift = uint(rInt(buf[12:13]))
	return rv
}

func (p PixelFormat) BytesPerPixel() int {
	return (p.Bits + 7) / 8
}

func (p PixelFormat) ReadPixel(buf []byte) (int, color.RGBA) {
	l := (p.Bits + 7) / 8
	var pixel uint = 0
	if l == 1 {
		pixel = uint(buf[0])
	} else if p.BigEndian {
		for i := 0; i < l; i++ {
			pixel = pixel<<8 | uint(buf[0])
		}
	} else {
		for i := 0; i < l; i++ {
			pixel = pixel<<8 | uint(buf[l-i-1])
		}
	}

	r := (pixel >> p.RedShift) & p.RedMax
	g := (pixel >> p.GreenShift) & p.GreenMax
	b := (pixel >> p.BlueShift) & p.BlueMax

	return l, color.RGBA{
		R: uint8((r * 0xff) / p.RedMax),
		G: uint8((g * 0xff) / p.GreenMax),
		B: uint8((b * 0xff) / p.BlueMax),
		A: 0xff,
	}
}

func (p PixelFormat) String() string {
	if p.TrueColour {
		return fmt.Sprintf("%d-bit true colour", p.Bits)
	} else {
		return fmt.Sprintf("%d-bit mapped", p.Bits)
	}
}
