package tls

// CertWriterOption is a function that configures a CertWriter
type CertWriterOption func(*certWriter)

// WithBasePath sets the base path for storing certificates
func WithBasePath(path string) CertWriterOption {
	return func(cw *certWriter) {
		if path != "" {
			cw.basePath = path
		}
	}
}

