BINARY_NAME=hide
OUTPUT_DIR=output

build:
	go build -o $(BINARY_NAME) ./cmd/hide

run:
	go run ./cmd/hide

test:
	go test -v -race ./...

clean:
	rm -f $(BINARY_NAME)
	rm -rf $(OUTPUT_DIR)

.PHONY: build run test clean full-test

full-test: build
	@echo "--- 1. Generating RSA Key Pair ---"
	./$(BINARY_NAME) keys -o $(OUTPUT_DIR)
	@echo "\n--- 2. Concealing PDF with RSA Public Key ---"
	./$(BINARY_NAME) conceal -i testdata/test.jpg -f testdata/test.pdf -o $(OUTPUT_DIR)/stego_rsa.png -k $(OUTPUT_DIR)/public.pem -s dct
	@echo "\n--- 3. Verifying Stego Image Integrity ---"
	./$(BINARY_NAME) verify -i $(OUTPUT_DIR)/stego_rsa.png
	@echo "\n--- 4. Analyzing Image Quality (PSNR) ---"
	./$(BINARY_NAME) analyze -o testdata/test.jpg -s $(OUTPUT_DIR)/stego_rsa.png -d $(OUTPUT_DIR)/heatmap.png
	@echo "\n--- 5. Revealing PDF with RSA Private Key ---"
	./$(BINARY_NAME) reveal -i $(OUTPUT_DIR)/stego_rsa.png -o $(OUTPUT_DIR)/revealed.pdf -k $(OUTPUT_DIR)/private.pem -s dct
	@echo "\n--- 6. Validating Result ---"
	@if diff testdata/test.pdf $(OUTPUT_DIR)/revealed.pdf; then \
		echo "✅ Success: Revealed PDF matches original."; \
	else \
		echo "❌ Failure: Revealed PDF does not match original."; \
		exit 1; \
	fi
