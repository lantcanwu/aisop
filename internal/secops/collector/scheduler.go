package collector

import (
	"fmt"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
)

type Scheduler struct {
	cron          *cron.Cron
	collectors    map[string]CollectorJob
	mu            sync.RWMutex
	onJobExecute  func(job *CollectorJob)
	onJobComplete func(job *CollectorJob, err error)
}

func NewScheduler() *Scheduler {
	return &Scheduler{
		cron:       cron.New(),
		collectors: make(map[string]CollectorJob),
	}
}

func (s *Scheduler) Start() {
	s.cron.Start()
}

func (s *Scheduler) Stop() {
	ctx := s.cron.Stop()
	<-ctx.Done()
}

func (s *Scheduler) AddCollector(config *CollectorConfig) error {
	if config.Schedule == "" {
		return fmt.Errorf("schedule is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	jobID, err := s.cron.AddFunc(config.Schedule, func() {
		s.executeCollector(config)
	})
	if err != nil {
		return err
	}

	s.collectors[config.ID] = CollectorJob{
		CollectorID: config.ID,
		Status:      CollectorStatusIdle,
	}

	fmt.Printf("Added collector %s with schedule %s\n", config.Name, config.Schedule)
	_ = jobID

	return nil
}

func (s *Scheduler) RemoveCollector(collectorID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.collectors, collectorID)
}

func (s *Scheduler) executeCollector(config *CollectorConfig) {
	job := &CollectorJob{
		CollectorID: config.ID,
		Status:      CollectorStatusRunning,
	}
	job.SetTimestamps()
	job.SetID()

	s.mu.Lock()
	s.collectors[config.ID] = *job
	s.mu.Unlock()

	if s.onJobExecute != nil {
		s.onJobExecute(job)
	}

	var eventsCount int
	var err error

	switch config.Type {
	case CollectorTypeAPI:
		collector := NewAPICollector(*config)
		events, err := collector.Run()
		if err == nil {
			eventsCount = len(events)
		}
	case CollectorTypeSIEM:
		collector := NewSIEMCollector(*config)
		events, err := collector.Run()
		if err == nil {
			eventsCount = len(events)
		}
	case CollectorTypeSTIX, CollectorTypeTAXII:
		collector := NewThreatIntelCollector(*config)
		events, err := collector.Run()
		if err == nil {
			eventsCount = len(events)
		}
	default:
		err = fmt.Errorf("unsupported collector type: %s", config.Type)
	}

	now := time.Now()
	job.CompletedAt = &now
	job.EventsCount = eventsCount

	if err != nil {
		job.Status = CollectorStatusFailed
		job.ErrorMessage = err.Error()
	} else {
		job.Status = CollectorStatusSuccess
	}

	s.mu.Lock()
	s.collectors[config.ID] = *job
	s.mu.Unlock()

	if s.onJobComplete != nil {
		s.onJobComplete(job, err)
	}
}

func (s *Scheduler) GetJob(collectorID string) (*CollectorJob, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	job, ok := s.collectors[collectorID]
	return &job, ok
}

func (s *Scheduler) ListJobs() []*CollectorJob {
	s.mu.RLock()
	defer s.mu.RUnlock()

	jobs := make([]*CollectorJob, 0, len(s.collectors))
	for _, job := range s.collectors {
		j := job
		jobs = append(jobs, &j)
	}

	return jobs
}

func (s *Scheduler) SetOnJobExecute(callback func(job *CollectorJob)) {
	s.onJobExecute = callback
}

func (s *Scheduler) SetOnJobComplete(callback func(job *CollectorJob, err error)) {
	s.onJobComplete = callback
}

type SchedulerService struct {
	scheduler *Scheduler
}

func NewSchedulerService() *SchedulerService {
	return &SchedulerService{
		scheduler: NewScheduler(),
	}
}

func (s *SchedulerService) Start() {
	s.scheduler.Start()
}

func (s *SchedulerService) Stop() {
	s.scheduler.Stop()
}

func (s *SchedulerService) AddCollector(config *CollectorConfig) error {
	return s.scheduler.AddCollector(config)
}

func (s *SchedulerService) RemoveCollector(collectorID string) {
	s.scheduler.RemoveCollector(collectorID)
}

func (s *SchedulerService) GetJob(collectorID string) (*CollectorJob, bool) {
	return s.scheduler.GetJob(collectorID)
}

func (s *SchedulerService) ListJobs() []*CollectorJob {
	return s.scheduler.ListJobs()
}

func (s *SchedulerService) TriggerManualRun(config *CollectorConfig) (*CollectorJob, error) {
	job := &CollectorJob{
		CollectorID: config.ID,
		Status:      CollectorStatusRunning,
	}
	job.SetTimestamps()
	job.SetID()

	go s.scheduler.executeCollector(config)

	return job, nil
}
