package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

type ProxyChecker struct {
	proxies []string
}

func NewProxyChecker(filename string) (*ProxyChecker, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("Ошибка: файл '%s' не найден", filename)
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		proxy := scanner.Text()
		if len(proxy) > 0 {
			proxies = append(proxies, proxy)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	fmt.Printf("Загружено %d прокси из файла '%s'.\n", len(proxies), filename)
	return &ProxyChecker{proxies: proxies}, nil
}

func (pc *ProxyChecker) CheckProxy(proxy string, wg *sync.WaitGroup) {
	defer wg.Done()

	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest("GET", "http://httpbin.org/ip", nil)
	if err != nil {
		fmt.Printf("Ошибка при создании запроса для прокси %s: %v\n", proxy, err)
		return
	}

	req.Header.Set("Proxy-Authorization", fmt.Sprintf("Basic %s", proxy))
	proxyURL := fmt.Sprintf("http://%s", proxy)
	req.URL.Host = proxyURL
	req.URL.Scheme = "http"

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Прокси %s не работает! Ошибка: %v\n", proxy, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			fmt.Printf("Прокси %s работает! Ответ: %s\n", proxy, result["origin"])
		}
	} else {
		fmt.Printf("Прокси %s не работает! Код ответа: %d\n", proxy, resp.StatusCode)
	}
}

func (pc *ProxyChecker) Run() {
	var wg sync.WaitGroup

	for _, proxy := range pc.proxies {
		wg.Add(1)
		go pc.CheckProxy(proxy, &wg)
	}

	wg.Wait()
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Использование: go run main.go <filename>")
		return
	}

	filename := os.Args[1]
	proxyChecker, err := NewProxyChecker(filename)
	if err != nil {
		fmt.Println(err)
		return
	}

	proxyChecker.Run()
}