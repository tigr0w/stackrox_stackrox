package restore

import (
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/utils"
)

const (
	idleTimeout = 5 * time.Minute
)

func (cmd *centralDbRestoreCommand) restore(impl func(file *os.File, deadline time.Time) error) error {
	deadline := time.Now().Add(cmd.timeout)

	file, err := os.Open(cmd.file)
	if err != nil {
		return errors.Wrapf(err, "opening backup file %q to restore", cmd.file)
	}
	defer utils.IgnoreError(file.Close)

	if err := impl(file, deadline); err != nil {
		return err
	}

	cmd.env.Logger().PrintfLn("Successfully restored DB")
	return nil
}
