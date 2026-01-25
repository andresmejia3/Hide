package stego

import (
	"image"
	"image/color"
	_ "image/gif"
	_ "image/jpeg"
	"math"
	"math/rand"
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
	defer file.Close()

	img, _, err := image.Decode(file)
	if err != nil {
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

func matchBitUint8(num uint8, index int, bit int) uint8 {
	// LSB Matching only applies to the least significant bit (index 0).
	// For other bits, we fall back to standard replacement.
	if index != 0 {
		if bit == 0 {
			return clearBitUint8(num, index)
		}
		return setBitUint8(num, index)
	}

	val := int(num)
	currentBit := val & 1
	if currentBit == bit {
		return num
	}

	// Randomly add or subtract 1 to flip the LSB
	if rand.Intn(2) == 0 {
		val++
	} else {
		val--
	}

	// Handle boundary conditions
	if val > 255 {
		val = 254 // 255 -> 254 flips LSB (1 -> 0)
	} else if val < 0 {
		val = 1 // 0 -> 1 flips LSB (0 -> 1)
	}

	return uint8(val)
}

// DCT Helpers
const blockSize = 8

func dct1d(in [blockSize]float64) [blockSize]float64 {
	var out [blockSize]float64
	c1 := math.Pi / (2.0 * blockSize)
	for u := 0; u < blockSize; u++ {
		sum := 0.0
		for x := 0; x < blockSize; x++ {
			sum += in[x] * math.Cos(float64(2*x+1)*float64(u)*c1)
		}
		alpha := 1.0
		if u == 0 {
			alpha = 1.0 / math.Sqrt(2)
		}
		out[u] = 0.5 * alpha * sum
	}
	return out
}

func idct1d(in [blockSize]float64) [blockSize]float64 {
	var out [blockSize]float64
	c1 := math.Pi / (2.0 * blockSize)
	for x := 0; x < blockSize; x++ {
		sum := 0.0
		for u := 0; u < blockSize; u++ {
			alpha := 1.0
			if u == 0 {
				alpha = 1.0 / math.Sqrt(2)
			}
			sum += alpha * in[u] * math.Cos(float64(2*x+1)*float64(u)*c1)
		}
		out[x] = 0.5 * sum
	}
	return out
}

func dct2d(block [blockSize][blockSize]float64) [blockSize][blockSize]float64 {
	var temp [blockSize][blockSize]float64
	for i := 0; i < blockSize; i++ {
		temp[i] = dct1d(block[i])
	}
	var out [blockSize][blockSize]float64
	for j := 0; j < blockSize; j++ {
		var col [blockSize]float64
		for i := 0; i < blockSize; i++ {
			col[i] = temp[i][j]
		}
		res := dct1d(col)
		for i := 0; i < blockSize; i++ {
			out[i][j] = res[i]
		}
	}
	return out
}

func idct2d(dct [blockSize][blockSize]float64) [blockSize][blockSize]float64 {
	var temp [blockSize][blockSize]float64
	for i := 0; i < blockSize; i++ {
		temp[i] = idct1d(dct[i])
	}
	var out [blockSize][blockSize]float64
	for j := 0; j < blockSize; j++ {
		var col [blockSize]float64
		for i := 0; i < blockSize; i++ {
			col[i] = temp[i][j]
		}
		res := idct1d(col)
		for i := 0; i < blockSize; i++ {
			out[i][j] = res[i]
		}
	}
	return out
}
