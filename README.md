## ✅ Check if Go is installed
go version

## ⬇️ Install Go (if not installed)
sudo apt update
sudo apt install golang-go -y

## 📁 Go to the agent project directory
cd path/to/your-agent-project

## 🛠️ Build the agent binary
make build

## 📦 Check the size of the built binary
make size

## 🚀 Run the compiled agent
./dist/ultahost-agent

## 🧹 Clean up build artifacts (optional)
make clean

## 📝 Optional: Build manually without Makefile (if needed)
go build -o dist/ultahost-agent ./cmd
