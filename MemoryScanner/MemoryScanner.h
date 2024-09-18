#pragma once

#include <QWidget>
#include <QListWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QProgressBar>
#include <QStatusBar>
#include <QFileDialog>
#include <QTextStream>
#include <QComboBox>
#include <QSpinBox>
#include <QCheckBox>
#include <QLabel>
#include <QDebug> 
#include <windows.h>

class MemoryScanner : public QWidget {
    Q_OBJECT

public:
    MemoryScanner();

private slots:
    void scanMemory();
    //void updateProcessList();
    //void filterProcesses();
    //void sortProcesses();
    //void searchMemoryRange();
   // void searchDifferentDataType();
    void saveResults();
    void loadResults();
    //void updateStatus(const QString& status);

private:
    void scanMemoryRange();
    void editMemory();
    DWORD getProcessID(const QString& processName);
    void listProcesses();
    //void initializeUI();
    //void updateProgressBar(int value);
    //void displayResults(const QString& results);

    QListWidget* processList;
    QLineEdit* searchBox;
    QProgressBar* progressBar;
    QStatusBar* statusBar;
    QComboBox* filterComboBox;
    QComboBox* sortComboBox;
    QLineEdit* rangeStartBox;
    QLineEdit* rangeEndBox;
    QComboBox* dataTypeComboBox;
    QPushButton* saveButton;
    QPushButton* loadButton;
    QPushButton* filterButton;
    QPushButton* sortButton;
    QPushButton* searchRangeButton;
    QPushButton* searchDataTypeButton;
    QCheckBox* customCheckBox;
    QLabel* resultLabel;
};
