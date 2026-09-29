// ds18b20.c — bit-banged 1-Wire for a single DS18B20.
//
// Timing from Maxim's 1-Wire application notes. Each read or write slot is
// under 70 µs and runs with interrupts masked, because ESP-NOW interrupts
// landing mid-slot corrupt the bit. The 480 µs reset pulse does not need
// that: stretching it is harmless, so only the presence sample is masked.
// Whatever still gets through is caught by the scratchpad CRC in the core,
// and the read is retried.

#include "ds18b20.h"

#include "cell_templog.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "rom/ets_sys.h"

static const char *TAG = "ds18b20";

static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;

#define CMD_SKIP_ROM        0xCC
#define CMD_CONVERT_T       0x44
#define CMD_READ_SCRATCHPAD 0xBE

#define CONVERSION_MS  800   // 12-bit conversion is 750 ms max
#define ATTEMPTS         3

static bool ow_reset(int gpio) {
    gpio_set_level(gpio, 0);
    ets_delay_us(490);
    portENTER_CRITICAL(&s_mux);
    gpio_set_level(gpio, 1);
    ets_delay_us(70);
    bool present = gpio_get_level(gpio) == 0;
    portEXIT_CRITICAL(&s_mux);
    ets_delay_us(420);
    return present;
}

static void ow_write_bit(int gpio, int bit) {
    portENTER_CRITICAL(&s_mux);
    gpio_set_level(gpio, 0);
    if (bit) {
        ets_delay_us(2);
        gpio_set_level(gpio, 1);
        ets_delay_us(63);
    } else {
        ets_delay_us(65);
        gpio_set_level(gpio, 1);
        ets_delay_us(2);
    }
    portEXIT_CRITICAL(&s_mux);
}

static int ow_read_bit(int gpio) {
    portENTER_CRITICAL(&s_mux);
    gpio_set_level(gpio, 0);
    ets_delay_us(2);
    gpio_set_level(gpio, 1);
    ets_delay_us(10);
    int bit = gpio_get_level(gpio);
    portEXIT_CRITICAL(&s_mux);
    ets_delay_us(55);
    return bit;
}

static void ow_write_byte(int gpio, uint8_t b) {
    for (int i = 0; i < 8; i++) {
        ow_write_bit(gpio, b & 1);
        b >>= 1;
    }
}

static uint8_t ow_read_byte(int gpio) {
    uint8_t b = 0;
    for (int i = 0; i < 8; i++) b |= (uint8_t)(ow_read_bit(gpio) << i);
    return b;
}

esp_err_t ds18b20_init(int gpio) {
    gpio_config_t cfg = {
        .pin_bit_mask = 1ULL << gpio,
        .mode = GPIO_MODE_INPUT_OUTPUT_OD,
        .pull_up_en = GPIO_PULLUP_ENABLE,   // backup only: use the 4.7 kΩ on the probe board
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    esp_err_t err = gpio_config(&cfg);
    if (err != ESP_OK) return err;
    gpio_set_level(gpio, 1);
    if (!ow_reset(gpio)) {
        ESP_LOGE(TAG, "no DS18B20 answered on GPIO%d — check wiring and the pull-up", gpio);
        return ESP_ERR_NOT_FOUND;
    }
    ESP_LOGI(TAG, "DS18B20 present on GPIO%d", gpio);
    return ESP_OK;
}

static int read_once(int gpio, int16_t *out_centi) {
    if (!ow_reset(gpio)) return CM_DS_ERR_NO_DEVICE;
    ow_write_byte(gpio, CMD_SKIP_ROM);
    ow_write_byte(gpio, CMD_CONVERT_T);
    vTaskDelay(pdMS_TO_TICKS(CONVERSION_MS));

    if (!ow_reset(gpio)) return CM_DS_ERR_NO_DEVICE;
    ow_write_byte(gpio, CMD_SKIP_ROM);
    ow_write_byte(gpio, CMD_READ_SCRATCHPAD);
    uint8_t sp[9];
    for (int i = 0; i < 9; i++) sp[i] = ow_read_byte(gpio);
    return cm_ds18b20_decode(sp, out_centi);
}

int ds18b20_read(int gpio, int16_t *out_centi) {
    int rc = CM_DS_ERR_NO_DEVICE;
    for (int attempt = 0; attempt < ATTEMPTS; attempt++) {
        rc = read_once(gpio, out_centi);
        if (rc == CM_DS_OK) return rc;
        // 85.00 °C straight after power-up is the reset value, not a reading.
        // A second conversion settles it; a probe that keeps saying 85 is
        // reported as such rather than logged as heat.
        ESP_LOGW(TAG, "read attempt %d: rc=%d", attempt + 1, rc);
    }
    return rc;
}
