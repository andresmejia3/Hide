package stego

import "errors"

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
}

func makeImageStepper(numBitsToUsePerChannel int, width int, height int, channelSize int, totalBitsToBeWritten int) *ImageStepper {
	return &ImageStepper{
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
	}
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
		self.x++
	}

	if self.x >= self.width {
		self.x = 0
		self.y++
	}

	if self.y >= self.height && self.numBitsWritten < self.totalBitsToBeWritten {
		return errors.New("more steps taken than pixels in the image")
	}

	return nil
}

func (self *ImageStepper) skipPixel() {
	self.numBitsWritten += 4
	self.x += 1

	if self.x >= self.width {
		self.x = 0
		self.y += 1
	}
}
