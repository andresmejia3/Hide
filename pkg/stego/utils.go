package stego

import (
	"image"
	"image/color"
	"os"
)

func colorToChannels(c color.Color) []uint8 {
	colorNRGBA := color.NRGBAModel.Convert(c).(color.NRGBA)
	return []uint8{colorNRGBA.R, colorNRGBA.G, colorNRGBA.B, colorNRGBA.A}
}

func getPixel(img *image.NRGBA, x int, y int) []uint8 {
	index := img.PixOffset(x, y)
	return img.Pix[index : index+4]
}

func loadImage(path string) (image.Image, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	img, _, err := image.Decode(file)
	if err != nil {
		return nil, err
	}

	if err := file.Close(); err != nil {
		return nil, err
	}

	return img, nil
}

func copyImage(img image.Image) *image.NRGBA {
	outputImage := image.NewNRGBA(img.Bounds())
	width := img.Bounds().Max.X
	height := img.Bounds().Max.Y

	for x := 0; x < width; x++ {
		for y := 0; y < height; y++ {
			pixel := img.At(x, y)
			outputImage.Set(x, y, pixel)
		}
	}
	return outputImage
}

func numBitsAvailable(width int, height int, channelSize int, numBitsToUsePerChannel int) int {
	if width == 0 || height == 0 || numBitsToUsePerChannel < 1 {
		return 0
	}
	return width * height * channelSize * numBitsToUsePerChannel
}

func getBit(num int, index int) int {
	mask := 1 << index
	if num&mask == 0 {
		return 0
	}
	return 1
}

func setBit(num int, index int) int {
	mask := 1 << index
	return num | mask
}

func clearBit(num int, index int) int {
	mask := ^(1 << index)
	return num & mask
}

func getBitUint8(num uint8, index int) int {
	mask := uint8(1 << index)
	if num&mask == 0 {
		return 0
	}
	return 1
}

func setBitUint8(num uint8, index int) uint8 {
	mask := uint8(1 << index)
	return num | mask
}

func clearBitUint8(num uint8, index int) uint8 {
	mask := uint8(^(1 << index))
	return num & mask
}
