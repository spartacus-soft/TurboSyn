#include <stdint.h>

// ɨ��״̬
typedef enum {
	SUCCESS = 0,
	CANCELLED = 1,
	COMPLETED = 2,
} TurboSynScanState;

// ɨ��ɹ�����ɵĽ��
typedef struct {
	// ɨ��״̬
	TurboSynScanState State;
	// TCP�˿�
	int32_t Port;
	// ��ǰIP���ݳ���
	int32_t IPLength;
	// ��ǰIP������
	uint8_t IPAddress[16];
} TurboSynScanResult;

// ɨ�����
typedef struct {
	// ��ǰIP����
	uint64_t CurrentCount;
	// Ҫɨ���IP������
	uint64_t TotalCount;
	// ��ǰɨ���IP���ݳ���
	int32_t IPLength;
	// ��ǰɨ���I������
	uint8_t IPAddress[16];
} TurboSynScanProgress;

// ɨ����
typedef void* TurboSynScanner;

// ɨ��ɹ��ص�
typedef void (*TurboSuccessCallback)(
	// ɨ����
	TurboSynScanResult scanResult,
	// �û��Զ������
	void* userParam);

// ɨ����Ȼص�
typedef void (*TurboProgressCallback)(
	// ɨ�����
	TurboSynScanProgress scanProgress,
	// �û��Զ������
	void* userParam);

// ����ɨ����
// ʧ���򷵻�NULL
extern "C" TurboSynScanner TurboSynCreateScanner(
	// CIDR��IP��ַ�ı����ݣ�һ��һ����¼
	const char* content);

// ��ʼɨ��
extern "C" bool TurboSynStartScan(
	// ɨ����
	TurboSynScanner scanner,
	// TCP�˿�
	int32_t port,
	// �ɹ��ص�
	TurboSuccessCallback successCallback,
	// ���Ȼص�
	TurboProgressCallback progressCallback,
	// �û��Զ������
	void* userParam);

// ȡ��ɨ����������ɨ������
extern "C" bool TurboSynCancelScan(TurboSynScanner scanner);

// �ͷ�ɨ����
extern "C" void TurboSynFreeScanner(TurboSynScanner scanner);