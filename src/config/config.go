package config

import (
    "context"
	"bufio"
	"log"
    "strings"
	"os"

    "github.com/quangtrieu1312/tmasque/constants"
)

func Load(ctx *context.Context) {
    configPath := constants.CONF_PATH
    file, err := os.Open(configPath)
    if err != nil {
        log.Fatalf("[FATAL] Failed to open config file %v: %v", configPath, err)
        os.Exit(1)
    }
    defer file.Close()
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if len(line) == 0 || strings.HasPrefix(line, "#") {
            continue
        }
        parts := strings.SplitN(line, "=", 2)
        if len(parts) != 2 {
            continue
        }
        key := strings.TrimSpace(parts[0])
        value := strings.TrimSpace(parts[1])
        if key == "" {
            continue
        }
        *ctx = context.WithValue(*ctx, key, value)
    }
}
