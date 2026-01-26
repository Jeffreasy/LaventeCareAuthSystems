//go:build ignore

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func main() {
	// 1. Read .env.local
	envMap := make(map[string]string)
	file, err := os.Open(".env.local")
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				// Remove quotes if present
				val = strings.Trim(val, "\"")
				val = strings.Trim(val, "'")
				envMap[key] = val
			}
		}
	} else {
		fmt.Println("Warning: .env.local not found, using system env")
	}

	// 2. Prepare Command
	cmd := exec.Command("go", "run", "cmd/migrate/main.go")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// 3. Set Env
	newEnv := os.Environ()
	for k, v := range envMap {
		newEnv = append(newEnv, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = newEnv

	// 4. Run
	fmt.Println("🚀 Running Migrations...")
	if err := cmd.Run(); err != nil {
		fmt.Printf("❌ Migration failed: %v\n", err)
		os.Exit(1)
	}
}
