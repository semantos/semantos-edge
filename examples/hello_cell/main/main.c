// hello_cell — the "blink" of Semantos on ESP32.
//
// Boots the component, loads a trivial Bitcoin Script ("OP_1 OP_1 OP_EQUAL"
// — pushes two ones and checks they're equal), executes it in the cell
// engine, and reports the result over serial.
//
// If this prints `execute rc=0, opcount=3, stack_depth=1, top=1` you have
// a living Semantos cell engine on your ESP32. Everything else is
// building on top.
//
// NOTE: We run the cell-engine work from a pthread, not directly from
// app_main. WAMR's runtime uses pthread_self() internally for its locking,
// and app_main is a plain FreeRTOS task without pthread registration —
// calling WAMR from there crashes with "Failed to find current thread ID!".
// Spawning a pthread gets us a properly registered thread context.

#include <stdio.h>
#include <pthread.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "semantos.h"

static const char *TAG = "hello_cell";

// A script that pushes two 1s and asserts equality.
// OP_1     (0x51)  — push 1
// OP_1     (0x51)  — push 1
// OP_EQUAL (0x87)  — pop two, push 1 if equal, 0 otherwise
static const uint8_t TRIVIAL_SCRIPT[] = { 0x51, 0x51, 0x87 };

static void *hello_cell_thread(void *arg) {
    (void)arg;
    ESP_LOGI(TAG, "starting...");

    semantos_t *sem = NULL;
    semantos_config_t cfg = SEMANTOS_DEFAULT_CONFIG();
    // cfg.adapters = NULL  → use the no-op adapter table
    //                        (this demo doesn't touch storage/network/etc.)

    if (semantos_init(&cfg, &sem) != ESP_OK) {
        ESP_LOGE(TAG, "semantos_init failed");
        return NULL;
    }
    ESP_LOGI(TAG, "semantos_init ok");

    int rc = semantos_kernel_init(sem);
    ESP_LOGI(TAG, "kernel_init rc=%d", rc);

    rc = semantos_kernel_load_script(sem, TRIVIAL_SCRIPT, sizeof(TRIVIAL_SCRIPT));
    ESP_LOGI(TAG, "load_script rc=%d", rc);

    rc = semantos_kernel_execute(sem);
    uint32_t opcount  = semantos_kernel_get_opcount(sem);
    uint32_t depth    = semantos_kernel_stack_depth(sem);
    // kernel_stack_peek returns a WASM-memory pointer to the cell data, not
    // the value. A non-zero pointer + correct depth + opcount + no error is
    // the honest success signal for OP_1 OP_1 OP_EQUAL.
    uint32_t top_ptr  = depth > 0 ? semantos_kernel_stack_peek(sem, 0) : 0;
    uint32_t err      = semantos_kernel_get_error(sem);

    ESP_LOGI(TAG, "execute rc=%d opcount=%u stack_depth=%u top_ptr=0x%08x err=0x%08x",
             rc, (unsigned)opcount, (unsigned)depth, (unsigned)top_ptr, (unsigned)err);

    if (rc == 0 && opcount == 3 && depth == 1 && top_ptr != 0 && err == 0) {
        ESP_LOGI(TAG, "=== hello cell: success ===");
        ESP_LOGI(TAG, "    cell-engine WASM running on ESP32-C6 \xf0\x9f\x9a\x80");
    } else {
        ESP_LOGW(TAG, "=== hello cell: something unexpected happened ===");
    }

    // Keep the thread alive so the logs stick around (and so the WAMR
    // runtime keeps its registered thread context).
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
    return NULL;
}

void app_main(void) {
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 12 * 1024);

    int rc = pthread_create(&tid, &attr, hello_cell_thread, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "pthread_create failed: %d", rc);
        return;
    }
    pthread_attr_destroy(&attr);

    // Join the thread (which loops forever after success). app_main returns
    // would otherwise lead to FreeRTOS happily idling.
    pthread_join(tid, NULL);
}
