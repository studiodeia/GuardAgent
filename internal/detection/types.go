package detection

import "context"

// MLModel represents a machine learning model used for detection.
type MLModel interface {
	Predict(ctx context.Context, text string) ([]PIIMatch, error)
}
