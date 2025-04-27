# Computer_Networks

This repository contains implementations of various network-related projects, showcasing skills in network programming, protocol implementation, and system design.

## Projects

### 1. Number Guessing Game Client
- A client-server implementation of a number guessing game
- Features:
  - Binary search algorithm for efficient guessing
  - Support for both plain and TLS-encrypted connections
  - JSON-based protocol communication
  - Command-line interface with configurable options

### 2. Web Crawler
- A responsible web crawler that discovers hidden flags on a target website
- Features:
  - HTTP GET/POST request handling
  - Cookie management for session persistence
  - URL parsing and normalization
  - Concurrent crawling with duplicate prevention
  - Regular expression-based flag detection

### 3. Content Delivery Network (CDN) Edge Server
- A proxy server that caches and delivers web content
- Features:
  - TLS termination with custom certificate generation
  - Persistent connection pooling to origin server
  - Thread-safe content caching
  - Support for HTTP/1.1 with keep-alive
  - Cache control based on content type and headers
  - Request/response logging

## Technical Highlights

- **Protocol Implementation**: Custom JSON-based protocol and HTTP handling
- **Security**: TLS encryption and certificate management
- **Performance**: Connection pooling and content caching
- **Concurrency**: Multi-threaded request handling
- **Robustness**: Error handling and retry mechanisms

## Requirements

- Python 3.x
- OpenSSL (for CDN project)
