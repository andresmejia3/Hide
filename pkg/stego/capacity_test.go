package stego

import "testing"

func TestGetCapacity(t *testing.T) {
	tests := []struct {
		name     string
		width    int
		height   int
		channels int
		bits     int
		strategy string
		want     int
	}{
		{
			name:     "LSB Standard",
			width:    100,
			height:   100,
			channels: 3,
			bits:     1,
			strategy: "lsb",
			want:     30000, // 100 * 100 * 3 * 1
		},
		{
			name:     "LSB High Density",
			width:    100,
			height:   100,
			channels: 4,
			bits:     4,
			strategy: "lsb",
			want:     160000, // 100 * 100 * 4 * 4
		},
		{
			name:     "LSB Matching",
			width:    50,
			height:   50,
			channels: 3,
			bits:     1,
			strategy: "lsb-matching",
			want:     7500, // 50 * 50 * 3 * 1
		},
		{
			name:     "DCT Standard",
			width:    100,
			height:   100,
			channels: 3, // Ignored by DCT
			bits:     1, // Ignored by DCT
			strategy: "dct",
			// DCT uses 8x8 blocks. 100/8 = 12 blocks.
			// Skips first row of blocks (y=0).
			// Capacity = blocksW * (blocksH - 1) = 12 * 11 = 132 bits.
			want: 132,
		},
		{
			name:     "DCT Small Image",
			width:    15,
			height:   15,
			channels: 3,
			bits:     1,
			strategy: "dct",
			want:     0, // 15/8 = 1 block. Height 1 block <= 1 -> 0 capacity.
		},
		{
			name:     "DCT Exact Blocks",
			width:    16,
			height:   16,
			channels: 3,
			bits:     1,
			strategy: "dct",
			want:     2, // 2 * (2-1) = 2 bits
		},
		{
			name:     "DCT Non-Divisible Dimensions",
			width:    103,
			height:   99,
			channels: 3,
			bits:     1,
			strategy: "dct",
			// 103/8 = 12 blocks wide. 99/8 = 12 blocks high.
			// Skips first row of blocks. Capacity = 12 * (12 - 1) = 132 bits.
			want:     132,
		},
		{
			name:     "Zero Width",
			width:    0,
			height:   100,
			channels: 3,
			bits:     1,
			strategy: "lsb",
			want:     0,
		},
		{
			name:     "Negative Bits (Invalid)",
			width:    100,
			height:   100,
			channels: 3,
			bits:     -1,
			strategy: "lsb",
			want:     0,
		},
		{
			name:     "Large Image LSB",
			width:    4000,
			height:   3000,
			channels: 3,
			bits:     2,
			strategy: "lsb",
			want:     72000000, // 4000 * 3000 * 3 * 2
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetCapacity(tt.width, tt.height, tt.channels, tt.bits, tt.strategy)
			if got != tt.want {
				t.Errorf("GetCapacity() = %d, want %d", got, tt.want)
			}
		})
	}
}