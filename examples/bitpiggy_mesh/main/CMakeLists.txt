idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES cell-mesh semantos
    PRIV_REQUIRES esp_timer driver mbedtls esp_driver_usb_serial_jtag esp_psram
    EMBED_FILES "embed/cell_deck.bin"
)
