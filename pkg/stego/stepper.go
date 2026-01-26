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
// It skips the first 35 pixels (3 metadata + 32 salt).
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

	// Shuffle indices starting from 35 to preserve metadata/salt pixels
	if count > 35 {
		r := rand.New(rand.NewSource(seed))
		r.Shuffle(count-35, func(i, j int) {
			indices[i+35], indices[j+35] = indices[j+35], indices[i+35]
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

// dctIterator traverses 8x8 blocks row by row.
// It starts at blockY=1 to reserve the first 8 pixel rows for the header.
type dctIterator struct {
	width, height  int
	blockX, blockY int
	blocksW        int
}

func newDctIterator(width, height int) *dctIterator {
	return &dctIterator{
		width:   width,
		height:  height,
		blocksW: width / 8,
		blockX:  0,
		blockY:  1, // Start at second row of blocks
	}
}

func (it *dctIterator) next() (int, int, bool) {
	// Check if the current block is within bounds
	if it.blockY*8+8 > it.height {
		return 0, 0, false
	}

	x, y := it.blockX, it.blockY

	it.blockX++
	if it.blockX >= it.blocksW {
		it.blockX = 0
		it.blockY++
	}
	return x, y, true
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

	iterator pixelIterator
}

func makeImageStepper(numBitsToUsePerChannel int, width int, height int, channelSize int, seed int64, strategy string) (*ImageStepper, error) {
	var it pixelIterator
	if strategy == "dct" {
		it = newDctIterator(width, height)
	} else if seed != 0 {
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
		iterator:               it,
	}

	// Prime the iterator so s.x and s.y reflect the first pixel
	x, y, ok := s.iterator.next()
	if !ok {
		return nil, errors.New("image too small for selected strategy")
	}
	s.x = x
	s.y = y

	return s, nil
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
		x, y, ok := self.iterator.next()
		if !ok {
			return errors.New("iterator exhausted: stepped past the last available pixel")
		}
		self.x = x
		self.y = y
	}

	return nil
}

func (self *ImageStepper) skipPixel() error {
	x, y, ok := self.iterator.next()
	if !ok {
		return errors.New("iterator exhausted: cannot skip pixel")
	}
	self.x = x
	self.y = y
	return nil
}
