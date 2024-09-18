#include <QApplication>
#include <QPushButton>
#include <QVBoxLayout>
#include <QDebug>
#include <QLineEdit>
#include <QListWidget>
#include <QProgressBar>
#include <QStatusBar>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>
#include <QInputDialog>
#include <QMessageBox>
#include <windows.h>
#include <tlhelp32.h>
#include "MemoryScanner.h"
#include <algorithm>

MemoryScanner::MemoryScanner() {
    QVBoxLayout* layout = new QVBoxLayout(this);

    processList = new QListWidget(this);
    layout->addWidget(processList);

    searchBox = new QLineEdit(this);
    searchBox->setPlaceholderText("Enter value to search");
    layout->addWidget(searchBox);

    QHBoxLayout* controlsLayout = new QHBoxLayout();
    QPushButton* scanButton = new QPushButton("Scan Memory", this);
    QPushButton* saveButton = new QPushButton("Save Results", this);
    QPushButton* loadButton = new QPushButton("Load Results", this);
    QPushButton* rangeScanButton = new QPushButton("Scan Memory Range", this);
    QPushButton* editMemoryButton = new QPushButton("Edit Memory", this);
    controlsLayout->addWidget(scanButton);
    controlsLayout->addWidget(rangeScanButton);
    controlsLayout->addWidget(editMemoryButton);
    controlsLayout->addWidget(saveButton);
    controlsLayout->addWidget(loadButton);
    layout->addLayout(controlsLayout);

    progressBar = new QProgressBar(this);
    layout->addWidget(progressBar);

    statusBar = new QStatusBar(this);
    layout->addWidget(statusBar);

    connect(scanButton, &QPushButton::clicked, this, &MemoryScanner::scanMemory);
    connect(rangeScanButton, &QPushButton::clicked, this, &MemoryScanner::scanMemoryRange);
    connect(editMemoryButton, &QPushButton::clicked, this, &MemoryScanner::editMemory);
    connect(saveButton, &QPushButton::clicked, this, &MemoryScanner::saveResults);
    connect(loadButton, &QPushButton::clicked, this, &MemoryScanner::loadResults);

    setLayout(layout);
    listProcesses();
}

void MemoryScanner::scanMemory() {
    QString searchTerm = searchBox->text();
    if (searchTerm.isEmpty()) {
        statusBar->showMessage("Please enter a value to search.");
        return;
    }

    bool ok;
    QString dataType = QInputDialog::getItem(this, "Select Data Type", "Data Type:", { "int", "float", "double" }, 0, false);
    if (dataType.isEmpty()) {
        statusBar->showMessage("Data type not selected.");
        return;
    }

    QVariant searchValue;
    if (dataType == "int") {
        searchValue = searchTerm.toInt(&ok);
    }
    else if (dataType == "float") {
        searchValue = searchTerm.toFloat(&ok);
    }
    else if (dataType == "double") {
        searchValue = searchTerm.toDouble(&ok);
    }

    if (!ok) {
        statusBar->showMessage("Invalid search value.");
        return;
    }

    if (processList->currentItem() == nullptr) {
        statusBar->showMessage("No process selected.");
        return;
    }

    QString processName = processList->currentItem()->text();
    DWORD processID = getProcessID(processName);
    if (processID == 0) {
        statusBar->showMessage("Failed to get process ID.");
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (hProcess == nullptr) {
        statusBar->showMessage("Failed to open process.");
        return;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    MEMORY_BASIC_INFORMATION memInfo;
    char* addr = (char*)sysInfo.lpMinimumApplicationAddress;

    progressBar->setValue(0);
    progressBar->setMaximum(100);
    progressBar->setTextVisible(true);

    QList<QString> results;

    while (addr < sysInfo.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(hProcess, addr, &memInfo, sizeof(memInfo))) {
            if (memInfo.State == MEM_COMMIT && memInfo.Protect == PAGE_READWRITE) {
                char* buffer = new char[memInfo.RegionSize];
                SIZE_T bytesRead;
                if (ReadProcessMemory(hProcess, addr, buffer, memInfo.RegionSize, &bytesRead)) {
                    for (SIZE_T i = 0; i < bytesRead; i += (dataType == "int" ? sizeof(int) : dataType == "float" ? sizeof(float) : sizeof(double))) {
                        QVariant value;
                        if (dataType == "int") {
                            value = *(int*)(buffer + i);
                        }
                        else if (dataType == "float") {
                            value = *(float*)(buffer + i);
                        }
                        else if (dataType == "double") {
                            value = *(double*)(buffer + i);
                        }
                        if (value == searchValue) {
                            results.append(QString("Found value at address: %1").arg(QString::number(reinterpret_cast<quintptr>(addr + i), 16)));
                        }
                    }
                }
                delete[] buffer;
            }
            addr += memInfo.RegionSize;
        }
        else {
            addr += sysInfo.dwPageSize;
        }
    }

    CloseHandle(hProcess);

    progressBar->setValue(100);
    statusBar->showMessage(QString("%1 results found.").arg(results.size()));

    // Display results
    processList->clear();
    processList->addItems(results);
}

void MemoryScanner::scanMemoryRange() {
    bool ok;
    QString startAddrStr = QInputDialog::getText(this, "Start Address", "Start Address (hex):", QLineEdit::Normal, "", &ok);
    if (!ok || startAddrStr.isEmpty()) return;

    QString endAddrStr = QInputDialog::getText(this, "End Address", "End Address (hex):", QLineEdit::Normal, "", &ok);
    if (!ok || endAddrStr.isEmpty()) return;

    quint64 startAddr = startAddrStr.toULongLong(&ok, 16);
    quint64 endAddr = endAddrStr.toULongLong(&ok, 16);

    if (!ok || startAddr >= endAddr) {
        statusBar->showMessage("Invalid address range.");
        return;
    }

    if (processList->currentItem() == nullptr) {
        statusBar->showMessage("No process selected.");
        return;
    }

    QString processName = processList->currentItem()->text();
    DWORD processID = getProcessID(processName);
    if (processID == 0) {
        statusBar->showMessage("Failed to get process ID.");
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (hProcess == nullptr) {
        statusBar->showMessage("Failed to open process.");
        return;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    MEMORY_BASIC_INFORMATION memInfo;
    char* addr = (char*)startAddr;

    progressBar->setValue(0);
    progressBar->setMaximum(100);
    progressBar->setTextVisible(true);

    QList<QString> results;

    while (addr < (char*)endAddr) {
        if (VirtualQueryEx(hProcess, addr, &memInfo, sizeof(memInfo))) {
            if (memInfo.State == MEM_COMMIT && memInfo.Protect == PAGE_READWRITE) {
                char* buffer = new char[memInfo.RegionSize];
                SIZE_T bytesRead;
                if (ReadProcessMemory(hProcess, addr, buffer, memInfo.RegionSize, &bytesRead)) {
                    // Example: Check for integers in the range
                    for (SIZE_T i = 0; i < bytesRead; i += sizeof(int)) {
                        int value = *(int*)(buffer + i);
                        // Just as a placeholder for actual logic
                        results.append(QString("Found integer value %1 at address: %2").arg(value).arg(QString::number(reinterpret_cast<quintptr>(addr + i), 16)));
                    }
                }
                delete[] buffer;
            }
            addr += memInfo.RegionSize;
        }
        else {
            addr += sysInfo.dwPageSize;
        }
    }

    CloseHandle(hProcess);

    progressBar->setValue(100);
    statusBar->showMessage(QString("%1 results found.").arg(results.size()));

    // Display results
    processList->clear();
    processList->addItems(results);
}

void MemoryScanner::editMemory() {
    bool ok;
    QString addressStr = QInputDialog::getText(this, "Memory Address", "Address (hex):", QLineEdit::Normal, "", &ok);
    if (!ok || addressStr.isEmpty()) return;

    quint64 address = addressStr.toULongLong(&ok, 16);
    if (!ok) {
        statusBar->showMessage("Invalid address.");
        return;
    }

    QString dataType = QInputDialog::getItem(this, "Select Data Type", "Data Type:", { "int", "float", "double" }, 0, false);
    if (dataType.isEmpty()) {
        statusBar->showMessage("Data type not selected.");
        return;
    }

    QString newValueStr = QInputDialog::getText(this, "New Value", QString("New %1 Value:").arg(dataType), QLineEdit::Normal, "", &ok);
    if (!ok || newValueStr.isEmpty()) return;

    bool success = false;
    HANDLE hProcess = nullptr;

    if (processList->currentItem() != nullptr) {
        QString processName = processList->currentItem()->text();
        DWORD processID = getProcessID(processName);
        if (processID != 0) {
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
        }
    }

    if (hProcess == nullptr) {
        statusBar->showMessage("Failed to open process.");
        return;
    }

    bool valueOk;
    if (dataType == "int") {
        int newValue = newValueStr.toInt(&valueOk);
        if (valueOk) {
            success = WriteProcessMemory(hProcess, (LPVOID)address, &newValue, sizeof(int), NULL);
        }
    }
    else if (dataType == "float") {
        float newValue = newValueStr.toFloat(&valueOk);
        if (valueOk) {
            success = WriteProcessMemory(hProcess, (LPVOID)address, &newValue, sizeof(float), NULL);
        }
    }
    else if (dataType == "double") {
        double newValue = newValueStr.toDouble(&valueOk);
        if (valueOk) {
            success = WriteProcessMemory(hProcess, (LPVOID)address, &newValue, sizeof(double), NULL);
        }
    }

    if (success) {
        statusBar->showMessage("Memory edited successfully.");
    }
    else {
        statusBar->showMessage("Failed to edit memory.");
    }

    CloseHandle(hProcess);
}

DWORD MemoryScanner::getProcessID(const QString& processName) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD processID = 0;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        qDebug() << "Failed to take process snapshot.";
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            if (QString::fromWCharArray(pe32.szExeFile) == processName) {
                processID = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }

    CloseHandle(hProcessSnap);
    return processID;
}

void MemoryScanner::listProcesses() {
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        qDebug() << "Failed to take process snapshot.";
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        qDebug() << "Failed to get first process.";
        CloseHandle(hProcessSnap);
        return;
    }

    QList<QString> processes;
    do {
        processes.append(QString::fromWCharArray(pe32.szExeFile));
    } while (Process32Next(hProcessSnap, &pe32));

    // Sort processes
    std::sort(processes.begin(), processes.end());

    // Display processes
    processList->clear();
    processList->addItems(processes);

    CloseHandle(hProcessSnap);
}

void MemoryScanner::saveResults() {
    QString fileName = QFileDialog::getSaveFileName(this, "Save Results", "", "Text Files (*.txt)");
    if (fileName.isEmpty()) return;

    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        statusBar->showMessage("Failed to open file for writing.");
        return;
    }

    QTextStream out(&file);
    for (int i = 0; i < processList->count(); ++i) {
        out << processList->item(i)->text() << "\n";
    }
    file.close();

    statusBar->showMessage("Results saved successfully.");
}

void MemoryScanner::loadResults() {
    QString fileName = QFileDialog::getOpenFileName(this, "Load Results", "", "Text Files (*.txt)");
    if (fileName.isEmpty()) return;

    QFile file(fileName);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        statusBar->showMessage("Failed to open file for reading.");
        return;
    }

    QTextStream in(&file);
    QStringList results;
    while (!in.atEnd()) {
        results.append(in.readLine());
    }
    file.close();

    processList->clear();
    processList->addItems(results);

    statusBar->showMessage("Results loaded successfully.");
}

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    MemoryScanner scanner;
    scanner.setWindowTitle("Memory Scanner | Developed by WRafi");
    scanner.resize(600, 500);
    scanner.show();

    return app.exec();
}
