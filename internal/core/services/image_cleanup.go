package services

import (
	"strings"

	"github.com/efangly/smtrack-authentication/internal/core/ports"
	"github.com/efangly/smtrack-authentication/pkg/logger"
)

// discardImage removes a stored picture nothing points at any more: one that
// was uploaded for a record that then failed to save, or the old one after a
// replacement was saved. Best effort: a failed delete is logged and never
// replaces the caller's own result.
func discardImage(files ports.FileUploadPort, folder string, picURL *string) {
	if picURL == nil || *picURL == "" {
		return
	}
	parts := strings.Split(*picURL, "/")
	name := parts[len(parts)-1]
	if err := files.Delete(folder, name); err != nil {
		logger.Warn("Failed to remove image", "error", err, "folder", folder, "file", name)
	}
}
