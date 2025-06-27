package utils

import (
	"fmt"
	"os/exec"
	"runtime"
)

// CopyToClipboard copies the given text to the system clipboard
func CopyToClipboard(text string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "echo "+text+"| clip")
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "linux":
		cmd = exec.Command("xclip", "-selection", "clipboard")
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdin pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start clipboard command: %v", err)
	}

	_, err = stdin.Write([]byte(text))
	if err != nil {
		return fmt.Errorf("failed to write to stdin: %v", err)
	}
	stdin.Close()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("clipboard command failed: %v", err)
	}

	return nil
}
