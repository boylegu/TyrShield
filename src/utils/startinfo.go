package utils

import (
	"image/png"
	"log"
	"os"
	"strings"

	"github.com/qeesung/image2ascii/convert"
)

func addBox(lines []string) []string {

	maxw := 0
	for _, l := range lines {
		if w := len(l); w > maxw {
			maxw = w
		}
	}

	horiz := strings.Repeat("─", maxw+2)
	top := "┌" + horiz + "┐"
	bot := "└" + horiz + "┘"

	boxed := []string{top}
	for _, l := range lines {
		padding := strings.Repeat(" ", maxw-len(l))
		boxed = append(boxed, "│ "+l+padding)
	}
	boxed = append(boxed, bot)
	return boxed
}

func RunASCIILogo() {

	f, _ := os.Open("assets/image/TyrShield_logo.png")
	defer f.Close()
	img, _ := png.Decode(f)

	converter := convert.NewImageConverter()
	ascii := converter.Image2ASCIIString(img, &convert.Options{
		FixedWidth:  50,
		FixedHeight: 20,
		Colored:     true,
	})

	artLines := strings.Split(ascii, "\n")

	note := []string{
		"SSH Protector v0.1.0",
		"High‑performance SSH protection",
		"©2025 MIT License",
	}
	boxedNote := addBox(note)

	const (
		gap        = 2
		noteOffset = 12
	)

	totalLines := len(artLines)
	if noteOffset+len(boxedNote) > totalLines {
		totalLines = noteOffset + len(boxedNote)
	}

	for i := 0; i < totalLines; i++ {

		var artPart string
		if i < len(artLines) {
			artPart = artLines[i]
		}

		padding := strings.Repeat(" ", gap)

		var notePart string
		if i >= noteOffset && i-noteOffset < len(boxedNote) {
			notePart = boxedNote[i-noteOffset]
		}

		log.Println(artPart + padding + notePart)
	}
}
