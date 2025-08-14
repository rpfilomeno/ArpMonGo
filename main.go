package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/gen2brain/beeep"
	"github.com/getlantern/systray"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
)

// Device represents a network device
type Device struct {
	ID         int       `json:"id"`
	IPAddress  string    `json:"ip_address"`
	MACAddress string    `json:"mac_address"`
	Hostname   string    `json:"hostname"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	IsActive   bool      `json:"is_active"`
}

// DiscordWebhook represents the payload for Discord webhook
type DiscordWebhook struct {
	Content string         `json:"content,omitempty"`
	Embeds  []DiscordEmbed `json:"embeds,omitempty"`
}

// DiscordEmbed represents an embed in Discord webhook
type DiscordEmbed struct {
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Color       int                 `json:"color"`
	Fields      []DiscordEmbedField `json:"fields"`
	Timestamp   string              `json:"timestamp"`
}

// DiscordEmbedField represents a field in Discord embed
type DiscordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

// Config holds application configuration
type Config struct {
	DiscordWebhookURL string
	ScanInterval      time.Duration
	DatabasePath      string
}

// LANMonitor manages the network monitoring functionality
type LANMonitor struct {
	config *Config
	db     *sql.DB
}

// NewLANMonitor creates a new LAN monitor instance
func NewLANMonitor(config *Config) (*LANMonitor, error) {
	db, err := sql.Open("sqlite3", config.DatabasePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	monitor := &LANMonitor{
		config: config,
		db:     db,
	}

	if err := monitor.initDatabase(); err != nil {
		return nil, fmt.Errorf("failed to initialize database: %v", err)
	}

	return monitor, nil
}

// initDatabase creates the necessary tables
func (lm *LANMonitor) initDatabase() error {
	query := `
	CREATE TABLE IF NOT EXISTS devices (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip_address TEXT NOT NULL,
		mac_address TEXT NOT NULL UNIQUE,
		hostname TEXT,
		first_seen DATETIME NOT NULL,
		last_seen DATETIME NOT NULL,
		is_active BOOLEAN NOT NULL DEFAULT 1
	);

	CREATE INDEX IF NOT EXISTS idx_mac_address ON devices(mac_address);
	CREATE INDEX IF NOT EXISTS idx_ip_address ON devices(ip_address);
	CREATE INDEX IF NOT EXISTS idx_last_seen ON devices(last_seen);
	`

	_, err := lm.db.Exec(query)
	return err
}

// getARPTable retrieves the ARP table from Windows
func (lm *LANMonitor) getARPTable() (map[string]Device, error) {
	cmd := exec.Command("arp", "-a")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute arp command: %v", err)
	}

	devices := make(map[string]Device)
	lines := strings.Split(string(output), "\n")

	// Regex to match ARP table entries
	// Format: IP Address        Physical Address      Type
	arpRegex := regexp.MustCompile(`^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+\w+`)

	for _, line := range lines {
		matches := arpRegex.FindStringSubmatch(strings.TrimSpace(line))
		if len(matches) == 3 {
			ip := matches[1]
			mac := strings.ToUpper(strings.ReplaceAll(matches[2], "-", ":"))

			// Skip invalid MAC addresses (like incomplete ones)
			if len(mac) == 17 && mac != "FF:FF:FF:FF:FF:FF" {
				hostname := lm.resolveHostname(ip)
				devices[mac] = Device{
					IPAddress:  ip,
					MACAddress: mac,
					Hostname:   hostname,
					LastSeen:   time.Now(),
					IsActive:   true,
				}
			}
		}
	}

	return devices, nil
}

// resolveHostname attempts to resolve hostname for an IP address
func (lm *LANMonitor) resolveHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// getDeviceByMAC retrieves a device from database by MAC address
func (lm *LANMonitor) getDeviceByMAC(macAddress string) (*Device, error) {
	query := `SELECT id, ip_address, mac_address, hostname, first_seen, last_seen, is_active 
			  FROM devices WHERE mac_address = ?`

	var device Device
	//var firstSeen, lastSeen string

	err := lm.db.QueryRow(query, macAddress).Scan(
		&device.ID, &device.IPAddress, &device.MACAddress,
		&device.Hostname, &device.FirstSeen, &device.LastSeen, &device.IsActive,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	//device.FirstSeen, _ = time.Parse("2006-01-02 15:04:05", firstSeen)
	//device.LastSeen, _ = time.Parse("2006-01-02 15:04:05", lastSeen)

	return &device, nil
}

// insertDevice inserts a new device into the database
func (lm *LANMonitor) insertDevice(device Device) error {
	query := `INSERT INTO devices (ip_address, mac_address, hostname, first_seen, last_seen, is_active)
			  VALUES (?, ?, ?, ?, ?, ?)`

	_, err := lm.db.Exec(query, device.IPAddress, device.MACAddress, device.Hostname,
		device.FirstSeen.Format("2006-01-02 15:04:05"),
		device.LastSeen.Format("2006-01-02 15:04:05"), device.IsActive)

	return err
}

// updateDevice updates an existing device in the database
func (lm *LANMonitor) updateDevice(device Device) error {
	query := `UPDATE devices SET ip_address = ?, hostname = ?, last_seen = ?, is_active = ?
			  WHERE mac_address = ?`

	_, err := lm.db.Exec(query, device.IPAddress, device.Hostname,
		device.LastSeen.Format("2006-01-02 15:04:05"), device.IsActive, device.MACAddress)

	return err
}

// sendDiscordNotification sends a Discord webhook notification
func (lm *LANMonitor) sendDiscordNotification(device Device, isNewDevice bool) error {
	if lm.config.DiscordWebhookURL == "" {
		return nil // No webhook configured
	}

	var title, description string
	var color int

	if isNewDevice {
		title = "🆕 New Device Detected"
		description = "A new device has joined the network"
		color = 0x00FF00 // Green
	} else {
		title = "🔄 Known Device Active"
		description = "A previously seen device is active again"
		color = 0xFFFF00 // Yellow
	}

	hostname := device.Hostname
	if hostname == "" {
		hostname = "Unknown"
	}

	embed := DiscordEmbed{
		Title:       title,
		Description: description,
		Color:       color,
		Timestamp:   device.LastSeen.Format(time.RFC3339),
		Fields: []DiscordEmbedField{
			{Name: "IP Address", Value: device.IPAddress, Inline: true},
			{Name: "MAC Address", Value: device.MACAddress, Inline: true},
			{Name: "Hostname", Value: hostname, Inline: true},
			{Name: "First Seen", Value: device.FirstSeen.Format("2006-01-02 15:04:05"), Inline: true},
			{Name: "Last Seen", Value: device.LastSeen.Format("2006-01-02 15:04:05"), Inline: true},
		},
	}

	webhook := DiscordWebhook{
		Embeds: []DiscordEmbed{embed},
	}

	jsonData, err := json.Marshal(webhook)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook data: %v", err)
	}

	resp, err := http.Post(lm.config.DiscordWebhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send Discord webhook: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("Discord webhook returned status code: %d", resp.StatusCode)
	}

	return nil
}

// markInactiveDevices marks devices as inactive if they haven't been seen recently
func (lm *LANMonitor) markInactiveDevices(activeMACs map[string]bool) error {
	// Mark devices as inactive if they weren't seen in the last scan
	placeholders := strings.Repeat("?,", len(activeMACs))
	if len(placeholders) > 0 {
		placeholders = placeholders[:len(placeholders)-1]
	}

	var args []interface{}
	for mac := range activeMACs {
		args = append(args, mac)
	}

	var query string
	if len(activeMACs) > 0 {
		query = fmt.Sprintf("UPDATE devices SET is_active = 0 WHERE mac_address NOT IN (%s)", placeholders)
	} else {
		query = "UPDATE devices SET is_active = 0"
	}

	_, err := lm.db.Exec(query, args...)
	return err
}

// scanNetwork performs a network scan and updates the database
func (lm *LANMonitor) scanNetwork(exePath string) error {
	log.Println("Starting network scan...")

	devices, err := lm.getARPTable()
	if err != nil {
		return fmt.Errorf("failed to get ARP table: %v", err)
	}

	log.Printf("Found %d active devices in ARP table", len(devices))

	activeMACs := make(map[string]bool)
	newDevicesCount := 0
	updatedDevicesCount := 0

	for mac, device := range devices {
		activeMACs[mac] = true

		existingDevice, err := lm.getDeviceByMAC(mac)
		if err != nil {
			log.Printf("Error checking existing device %s: %v", mac, err)
			continue
		}

		if existingDevice == nil {
			// New device
			device.FirstSeen = device.LastSeen
			if err := lm.insertDevice(device); err != nil {
				log.Printf("Error inserting new device %s: %v", mac, err)
				continue
			}

			log.Printf("New device detected: %s (%s) - %s", device.IPAddress, device.MACAddress, device.Hostname)
			beeep.Notify("New device detected", fmt.Sprintf("%s (%s) - %s", device.IPAddress, device.MACAddress, device.Hostname), filepath.Join(exePath, "monitor.png"))

			if err := lm.sendDiscordNotification(device, true); err != nil {
				log.Printf("Error sending Discord notification for new device %s: %v", mac, err)
			}

			newDevicesCount++
		} else {
			// Update existing device
			device.FirstSeen = existingDevice.FirstSeen
			if err := lm.updateDevice(device); err != nil {
				log.Printf("Error updating device %s: %v", mac, err)
				continue
			}

			// Send notification if device was previously inactive
			if !existingDevice.IsActive {
				log.Printf("Previously inactive device is now active: %s (%s) first seen %s", device.IPAddress, device.MACAddress, device.FirstSeen.Format("2006-01-02 15:04:05"))
				if err := lm.sendDiscordNotification(device, false); err != nil {
					log.Printf("Error sending Discord notification for reactivated device %s: %v", mac, err)
				}
			}

			updatedDevicesCount++
		}
	}

	// Mark inactive devices
	if err := lm.markInactiveDevices(activeMACs); err != nil {
		log.Printf("Error marking inactive devices: %v", err)
	}

	log.Printf("Scan complete: %d new devices, %d updated devices", newDevicesCount, updatedDevicesCount)
	return nil
}

// Start begins the monitoring process
func (lm *LANMonitor) Start(exePath string) {
	beeep.Notify("Monitoring", string("started..."), filepath.Join(exePath, "monitor.png"))
	log.Println("Starting LAN monitor...")
	log.Printf("Scan interval: %v", lm.config.ScanInterval)
	log.Printf("Database path: %s", lm.config.DatabasePath)

	if lm.config.DiscordWebhookURL != "" {
		log.Println("Discord notifications enabled")
	} else {
		log.Println("Discord notifications disabled (no webhook URL provided)")
	}

	// Perform initial scan
	if err := lm.scanNetwork(exePath); err != nil {
		log.Printf("Error during initial scan: %v", err)
	}

	// Start periodic scanning
	ticker := time.NewTicker(lm.config.ScanInterval)
	defer ticker.Stop()

	for range ticker.C {
		if err := lm.scanNetwork(exePath); err != nil {
			log.Printf("Error during scan: %v", err)
		}
	}
}

// Close closes the database connection
func (lm *LANMonitor) Close() error {
	return lm.db.Close()
}

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
		os.Exit(1)
	}

	exePath, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	beeep.AppName = "ARPMonGo"

	// Configuration - modify these values as needed
	config := &Config{
		DiscordWebhookURL: os.Getenv("DISCORD_WEBHOOK_URL"), // Set this environment variable
		ScanInterval:      5 * time.Minute,                  // Scan every 5 minutes
		DatabasePath:      "lan_monitor.db",                 // SQLite database file
	}

	// You can also set the webhook URL directly here instead of using environment variable:
	// config.DiscordWebhookURL = "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL_HERE"

	monitor, err := NewLANMonitor(config)
	if err != nil {
		log.Fatalf("Failed to create LAN monitor: %v", err)
	}
	defer monitor.Close()

	go monitor.Start(exePath)

	systray.Run(func() {

		systray.SetTitle("ArpMonGo")
		systray.SetTooltip("ArpMonGo")
		systray.SetIcon(loadIcon("monitor.ico"))

		mQuit := systray.AddMenuItem("Quit", "Quit the app")

		go func() {
			for {
				select {
				case <-mQuit.ClickedCh:
					systray.Quit()
					return
				}
			}
		}()

	}, func() {
		// Cleanup
		os.Exit(1)

	})

}

func loadIcon(filename string) []byte {
	// Read the entire ICO file
	iconBytes, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("Error loading icon: %v", err)
		return nil
	}
	return iconBytes
}
