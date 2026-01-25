package stego

import (
	"errors"
	"math/rand"
)

// pixelIterator defines a strategy for traversing image pixels.
type pixelIterator interface {
	next() (x, y int, ok bool)
}

// linearIterator traverses pixels row by row, from top-left to bottom-right.
type linearIterator struct {
	width, height int
	x, y          int
}

func newLinearIterator(width, height int) *linearIterator {
	return &linearIterator{width: width, height: height}
}

func (it *linearIterator) next() (int, int, bool) {
	if it.y >= it.height {
		return 0, 0, false
	}
	x, y := it.x, it.y
	it.x++
	if it.x >= it.width {
		it.x = 0
		it.y++
	}
	return x, y, true
}

// randomIterator traverses pixels in a pseudo-random order determined by a seed.
// It skips the first two pixels (0,0 and 0,1 or 1,0) which are reserved for metadata.
type randomIterator struct {
	indices []int
	current int
	width   int
}

func newRandomIterator(width, height int, seed int64) *randomIterator {
	count := width * height
	indices := make([]int, count)
	for i := 0; i < count; i++ {
		indices[i] = i
	}

	// Shuffle indices starting from 2 to preserve metadata pixels
	if count > 2 {
		r := rand.New(rand.NewSource(seed))
		r.Shuffle(count-2, func(i, j int) {
			indices[i+2], indices[j+2] = indices[j+2], indices[i+2]
		})
	}
	return &randomIterator{indices: indices, width: width}
}

func (it *randomIterator) next() (int, int, bool) {
	if it.current >= len(it.indices) {
		return 0, 0, false
	}
	idx := it.indices[it.current]
	it.current++
	return idx % it.width, idx / it.width, true
}

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

	iterator pixelIterator
}

func makeImageStepper(numBitsToUsePerChannel int, width int, height int, channelSize int, totalBitsToBeWritten int, seed int64) *ImageStepper {
	var it pixelIterator
	if seed != 0 {
		it = newRandomIterator(width, height, seed)
	} else {
		it = newLinearIterator(width, height)
	}

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
		iterator:               it,
	}

	// Prime the iterator so s.x and s.y reflect the first pixel
	x, y, _ := s.iterator.next()
	s.x = x
	s.y = y

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
		// Move to next pixel
		x, y, ok := self.iterator.next()
		if !ok && self.numBitsWritten < self.totalBitsToBeWritten {
			return errors.New("more steps taken than pixels in the image")
		}
		self.x = x
		self.y = y
	}

	return nil
}

func (self *ImageStepper) skipPixel() {
	self.numBitsWritten += 4
	// Just advance the iterator
	x, y, _ := self.iterator.next()
	self.x = x
	self.y = y
}
