idf_component_register(
    SRCS "cold_chain_main.c"
    INCLUDE_DIRS "."
    REQUIRES
        cell-mesh
        nvs_flash
        esp_wifi
        esp_http_client
        esp_event
        esp_timer
        mbedtls
        freertos
        log
)
