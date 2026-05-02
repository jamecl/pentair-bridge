idf_component_register(
  SRCS "main.c"
  INCLUDE_DIRS "."
  REQUIRES
    driver
    freertos
    esp_http_server
    esp_wifi
    esp_netif
    esp_event
    esp_timer
    nvs_flash
    lwip
)

