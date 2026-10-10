// Command pixelart renders Foca.app's pixel-art icons from the grids in
// art.go, scaling by whole pixels so the edges stay hard:
//
//	go run ./scripts/pixelart apps/macos/Resources
//
// It writes the menu-bar template images (black on transparent, which macOS
// tints for light and dark menu bars) and Foca.iconset, which
// scripts/build-darwin.sh turns into Foca.icns. With -preview DIR it also
// writes large previews.
package main

import (
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	preview := flag.String("preview", "", "also write large previews to this directory")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: pixelart [-preview DIR] OUT-DIR")
		os.Exit(2)
	}
	if err := run(flag.Arg(0), *preview); err != nil {
		fmt.Fprintln(os.Stderr, "pixelart:", err)
		os.Exit(1)
	}
}

func run(out, preview string) error {
	menu, err := parse(menuBar, templatePalette)
	if err != nil {
		return fmt.Errorf("menu bar: %w", err)
	}
	warn, err := parse(menuBarWarning, templatePalette)
	if err != nil {
		return fmt.Errorf("menu bar warning: %w", err)
	}
	app, err := parse(appIcon, appPalette)
	if err != nil {
		return fmt.Errorf("app icon: %w", err)
	}
	files := map[string]image.Image{
		"MenuBarIcon.png":           menu,
		"MenuBarIcon@2x.png":        scale(menu, 2),
		"MenuBarIconWarning.png":    warn,
		"MenuBarIconWarning@2x.png": scale(warn, 2),
	}
	// Every size an .iconset holds: icon_<n>x<n>[@2x].png.
	for _, n := range []int{16, 32, 128, 256, 512} {
		for _, f := range []int{1, 2} {
			name := fmt.Sprintf("Foca.iconset/icon_%dx%d.png", n, n)
			if f == 2 {
				name = fmt.Sprintf("Foca.iconset/icon_%dx%d@2x.png", n, n)
			}
			files[name] = icon(app, n*f)
		}
	}
	for name, img := range files {
		if err := write(filepath.Join(out, name), img); err != nil {
			return err
		}
	}
	if preview != "" {
		for name, img := range map[string]image.Image{"menubar.png": scale(menu, 16), "menubar-warning.png": scale(warn, 16), "app.png": icon(app, 512)} {
			if err := write(filepath.Join(preview, name), onChecks(img)); err != nil {
				return err
			}
		}
	}
	return nil
}

// parse turns a grid, one character per pixel, into an image.
func parse(grid string, palette map[rune]color.NRGBA) (*image.NRGBA, error) {
	rows := strings.Split(strings.Trim(grid, "\n"), "\n")
	w := len([]rune(rows[0]))
	img := image.NewNRGBA(image.Rect(0, 0, w, len(rows)))
	for y, row := range rows {
		if len([]rune(row)) != w {
			return nil, fmt.Errorf("row %d is %d wide, not %d", y+1, len([]rune(row)), w)
		}
		for x, r := range row {
			c, ok := palette[r]
			if !ok {
				return nil, fmt.Errorf("row %d: no colour for %q", y+1, r)
			}
			img.SetNRGBA(x, y, c)
		}
	}
	return img, nil
}

// scale enlarges by a whole factor, each pixel a block.
func scale(src *image.NRGBA, f int) *image.NRGBA {
	b := src.Bounds()
	dst := image.NewNRGBA(image.Rect(0, 0, b.Dx()*f, b.Dy()*f))
	for y := 0; y < dst.Bounds().Dy(); y++ {
		for x := 0; x < dst.Bounds().Dx(); x++ {
			dst.SetNRGBA(x, y, src.NRGBAAt(x/f, y/f))
		}
	}
	return dst
}

// fit renders src at size×size: the largest whole scale that fits, centred.
// Below the grid's own size it samples nearest pixels.
func fit(src *image.NRGBA, size int) *image.NRGBA {
	n := src.Bounds().Dx()
	if size < n {
		dst := image.NewNRGBA(image.Rect(0, 0, size, size))
		for y := 0; y < size; y++ {
			for x := 0; x < size; x++ {
				dst.SetNRGBA(x, y, src.NRGBAAt(x*n/size, y*n/size))
			}
		}
		return dst
	}
	big := scale(src, size/n)
	dst := image.NewNRGBA(image.Rect(0, 0, size, size))
	off := (size - big.Bounds().Dx()) / 2
	for y := 0; y < big.Bounds().Dy(); y++ {
		for x := 0; x < big.Bounds().Dx(); x++ {
			dst.SetNRGBA(x+off, y+off, big.NRGBAAt(x, y))
		}
	}
	return dst
}

// icon renders the app icon at size×size inside the margin macOS gives app
// icons: the artwork takes about four fifths of the canvas, centred.
func icon(src *image.NRGBA, size int) *image.NRGBA {
	art := fit(src, size*4/5)
	dst := image.NewNRGBA(image.Rect(0, 0, size, size))
	off := (size - art.Bounds().Dx()) / 2
	for y := 0; y < art.Bounds().Dy(); y++ {
		for x := 0; x < art.Bounds().Dx(); x++ {
			dst.SetNRGBA(x+off, y+off, art.NRGBAAt(x, y))
		}
	}
	return dst
}

// onChecks puts a preview on a light checkerboard, so transparency shows.
func onChecks(src image.Image) *image.NRGBA {
	b := src.Bounds()
	dst := image.NewNRGBA(b)
	for y := 0; y < b.Dy(); y++ {
		for x := 0; x < b.Dx(); x++ {
			bg := color.NRGBA{235, 235, 235, 255}
			if (x/8+y/8)%2 == 0 {
				bg = color.NRGBA{205, 205, 205, 255}
			}
			c := color.NRGBAModel.Convert(src.At(x, y)).(color.NRGBA)
			a := uint32(c.A)
			mix := func(f, g uint8) uint8 { return uint8((uint32(f)*a + uint32(g)*(255-a)) / 255) }
			dst.SetNRGBA(x, y, color.NRGBA{mix(c.R, bg.R), mix(c.G, bg.G), mix(c.B, bg.B), 255})
		}
	}
	return dst
}

func write(path string, img image.Image) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := png.Encode(f, img); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
