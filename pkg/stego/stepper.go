package stego

import (
	"errors"
	"math/rand"
)

type ImageStepper struct {
	x                      int
	y                      int
	channel                int
	numBitsWritten         int
	bitIndexOffset         int
	numBitsToUsePerChannel int
	width                  int
	height                 int
	channelSize            int
	totalBitsToBeWritten   int

	// New fields for randomization
	currentPixelIndex int
	pixelIndices      []int
}

func makeImageStepper(numBitsToUsePerChannel int, width int, height int, channelSize int, totalBitsToBeWritten int, seed int64) *ImageStepper {
	s := &ImageStepper{
		x:                      0,
		y:                      0,
		channel:                0,
		numBitsWritten:         0,
		bitIndexOffset:         0,
		numBitsToUsePerChannel: numBitsToUsePerChannel,
		width:                  width,
		height:                 height,
		channelSize:            channelSize,
		totalBitsToBeWritten:   totalBitsToBeWritten,
		currentPixelIndex:      0,
	}

	if seed != 0 {
		count := width * height
		s.pixelIndices = make([]int, count)
		for i := 0; i < count; i++ {
			s.pixelIndices[i] = i
		}

		// Shuffle indices starting from 2 (preserve metadata pixels 0 and 1)
		if count > 2 {
			r := rand.New(rand.NewSource(seed))
			r.Shuffle(count-2, func(i, j int) {
				realI := i + 2
				realJ := j + 2
				s.pixelIndices[realI], s.pixelIndices[realJ] = s.pixelIndices[realJ], s.pixelIndices[realI]
			})
		}
	}

	return s
}

func (self *ImageStepper) step() error {
	self.numBitsWritten++
	self.bitIndexOffset++

	if self.bitIndexOffset >= self.numBitsToUsePerChannel {
		self.bitIndexOffset = 0
		self.channel++
	}

	if self.channel >= self.channelSize {
		self.channel = 0
		self.currentPixelIndex++

		if self.pixelIndices != nil {
			// Random mode
			if self.currentPixelIndex < len(self.pixelIndices) {
				idx := self.pixelIndices[self.currentPixelIndex]
				self.x = idx % self.width
				self.y = idx / self.width
			}
		} else {
			// Linear mode
			self.x++
			if self.x >= self.width {
				self.x = 0
				self.y++
			}
		}
	}

	// Check bounds
	isOutOfBounds := false
	if self.pixelIndices != nil {
		isOutOfBounds = self.currentPixelIndex >= len(self.pixelIndices)
	} else {
		isOutOfBounds = self.y >= self.height
	}

	if isOutOfBounds && self.numBitsWritten < self.totalBitsToBeWritten {
		return errors.New("more steps taken than pixels in the image")
	}

	return nil
}

func (self *ImageStepper) skipPixel() {
	self.numBitsWritten += 4
	self.currentPixelIndex++

	if self.pixelIndices != nil {
		if self.currentPixelIndex < len(self.pixelIndices) {
			idx := self.pixelIndices[self.currentPixelIndex]
			self.x = idx % self.width
			self.y = idx / self.width
		}
	} else {
		self.x++
		if self.x >= self.width {
			self.x = 0
			self.y++
		}
	}
}
