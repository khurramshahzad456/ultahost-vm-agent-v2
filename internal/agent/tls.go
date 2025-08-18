//go:build !windows
// +build !windows

package agent

// func clientTLSConfig(caPath, certPath, keyPath string) (*tls.Config, error) {
// 	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
// 	if err != nil {
// 		return nil, fmt.Errorf("load client cert: %w", err)
// 	}
// 	caPEM, err := os.ReadFile(caPath)
// 	if err != nil {
// 		return nil, fmt.Errorf("read ca: %w", err)
// 	}
// 	pool := x509.NewCertPool()
// 	pool.AppendCertsFromPEM(caPEM)
// 	return &tls.Config{
// 		Certificates: []tls.Certificate{cert},
// 		RootCAs:      pool,
// 		MinVersion:   tls.VersionTLS12,
// 	}, nil
// }
