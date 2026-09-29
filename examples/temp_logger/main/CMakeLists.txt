idf_component_register(
    SRCS "main.c" "ds18b20.c" "tlog_store.c"
    INCLUDE_DIRS "."
    REQUIRES cell-mesh semantos
    PRIV_REQUIRES esp_timer driver mbedtls esp_driver_usb_serial_jtag nvs_flash esp_partition
)
