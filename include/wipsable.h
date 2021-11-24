#ifndef __WIPSABLE_H__
#define __WIPSABLE_H__

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <pthread.h>

class WipsCall {
private:
  uint64_t _called = 0;
  std::chrono::duration<double> _longest;
  std::chrono::system_clock::time_point _last;
  pthread_t _pid;

public:
  WipsCall() { _pid = pthread_self(); }
  uint64_t called() const { //
    return _called;
  }
  std::chrono::duration<double> longest() const { //
    return _longest;
  }
  std::chrono::system_clock::time_point last() const { //
    return _last;
  }
  void update() {
    auto now = std::chrono::system_clock::now();
    if (_called) {
      if ((now - _last) > _longest) {
        _longest = now - _last;
      }
    }
    _last = now;
    _called++;
  }
};

class Wipsable {
private:
  std::condition_variable _destructor_cv;
  std::mutex _destructor_mutex;
  bool _wips_running = false;
  std::atomic<int> _running_count = ATOMIC_VAR_INIT(0);
  std::map<std::string, WipsCall> _called;

public:
  std::map<std::string, WipsCall> wipscall() { //
    return _called;
  }

  WipsCall wipscall(const std::string &run_name) {
    const std::string n = name() + "." + run_name;
    return _called[n];
  }

  void regist_wips_run(const std::string &run_name) {
    const std::string n = name() + "." + run_name;
    _running_count++;
    _called[n] = WipsCall();
  }

  void remove_wips_run() {
    _running_count--;
    _destructor_cv.notify_all();
  }

  bool wips_running(const std::string &run_name) {
    const std::string n = name() + "." + run_name;
    _called[n].update();
    return _wips_running;
  }

  bool wips_run() {
    _wips_running = true;
    return run();
  }

  void wips_run_wait() {
    _wips_running = false;
    std::unique_lock<std::mutex> lock(_destructor_mutex);
    _destructor_cv.wait(lock, [&]() { //
      return _running_count.load() == 0;
    });
  }

private:
  virtual bool run() = 0;

public:
  Wipsable(const nlohmann::json &config) {}
  virtual const std::string name() = 0;
  virtual ~Wipsable() {}
};

// sample code
/*
class Test {

private:

  nlohmann::json _config;
  int *val;

public:

  Test(const nlohmann::json &config): Wipsable(config) {
    _config = config;
    val = new int(10);
  }

  void run() {
    auto thread_func = []() {
      regist_wips_run("test_thread");

      while (wips_running("test_thread")) {
        // something
      }

      remove_wips_run();
    };

    auto th = thread(thread_func);
  }

  ~Test() {
    wips_run_wait(); // wait for registed threads

    delete val;
  }

  const std::string name() {
    return "Test"
  }
};

*/
#endif
