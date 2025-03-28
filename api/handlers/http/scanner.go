package http

import (
	"errors"
	"fmt"
	"log"

	"github.com/gofiber/fiber/v2"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/context"
)

func CreateScanner(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())
		var req pb.CreateScannerRequest
		if err := c.BodyParser(&req); err != nil {
			// Log the error for debugging
			context.GetLogger(c.UserContext()).Error("Failed to parse request body", "error", err)
			return fiber.ErrBadRequest
		}

		response, err := srv.CreateScanner(c.UserContext(), &req)
		if err != nil {
			if errors.Is(err, service.ErrInvalidScannerInput) {
				return fiber.ErrBadRequest
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		return c.Status(fiber.StatusCreated).JSON(response)
	}
}

func GetScanner(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		id := c.Params("id")
		if id == "" {
			log.Printf("Scanner ID is empty")
			return fiber.ErrBadRequest
		}

		log.Printf("Looking up scanner with ID: %s", id)

		response, err := srv.GetScanner(c.UserContext(), &pb.GetScannerRequest{Id: id})
		if err != nil {
			log.Printf("Error retrieving scanner: %v", err)
			if errors.Is(err, service.ErrScannerNotFound) {
				return fiber.ErrNotFound
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		return c.JSON(response)
	}
}

func UpdateScanner(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		id := c.Params("id")
		if id == "" {
			return fiber.ErrBadRequest
		}

		var req pb.UpdateScannerRequest
		if err := c.BodyParser(&req); err != nil {
			return fiber.ErrBadRequest
		}
		req.Id = id

		response, err := srv.UpdateScanner(c.UserContext(), &req)
		if err != nil {
			if errors.Is(err, service.ErrScannerNotFound) {
				return fiber.ErrNotFound
			} else if errors.Is(err, service.ErrInvalidScannerInput) {
				return fiber.ErrBadRequest
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		return c.JSON(response)
	}
}

func DeleteScanner(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		id := c.Params("id")
		if id == "" {
			context.GetLogger(c.UserContext()).Error("Scanner ID is empty")
			return fiber.ErrBadRequest
		}

		context.GetLogger(c.UserContext()).Info("Deleting scanner", "id", id)

		err := srv.DeleteScanner(c.UserContext(), &pb.DeleteScannerRequest{Id: id})
		if err != nil {
			context.GetLogger(c.UserContext()).Error("Error deleting scanner", "id", id, "error", err)
			if errors.Is(err, service.ErrScannerNotFound) {
				return fiber.ErrNotFound
			}
			if errors.Is(err, service.ErrInvalidScannerInput) {
				return fiber.ErrBadRequest
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		context.GetLogger(c.UserContext()).Info("Successfully deleted scanner", "id", id)
		return c.Status(fiber.StatusNoContent).Send(nil)
	}
}

func DeleteScanners(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		var req pb.DeleteScannersRequest
		if err := c.BodyParser(&req); err != nil {
			context.GetLogger(c.UserContext()).Error("Failed to parse request body", "error", err)
			return fiber.ErrBadRequest
		}

		context.GetLogger(c.UserContext()).Info("Batch deleting scanners", "count", len(req.GetIds()))

		if len(req.GetIds()) == 0 {
			context.GetLogger(c.UserContext()).Warn("Empty scanner ID list provided")
			return c.Status(fiber.StatusNoContent).Send(nil)
		}

		err := srv.DeleteScanners(c.UserContext(), &req)
		if err != nil {
			context.GetLogger(c.UserContext()).Error("Error batch deleting scanners", "error", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		context.GetLogger(c.UserContext()).Info("Successfully batch deleted scanners")
		return c.Status(fiber.StatusNoContent).Send(nil)
	}
}
func ListScanners(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		req := &pb.ListScannersRequest{
			NameFilter: c.Query("name"),
			TypeFilter: c.Query("type"),
		}

		if enabledQuery := c.Query("enabled"); enabledQuery == "true" {
			req.EnabledFilter = true
		}

		response, err := srv.ListScanners(c.UserContext(), req)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		// Add debug logging here
		fmt.Printf("Scanners found: %+v\n", response)

		return c.JSON(response)
	}
}

func BatchUpdateScannersEnabled(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		var req pb.BatchUpdateScannersEnabledRequest
		if err := c.BodyParser(&req); err != nil {
			context.GetLogger(c.UserContext()).Error("Failed to parse request body", "error", err)
			return fiber.ErrBadRequest
		}

		context.GetLogger(c.UserContext()).Info("Batch updating scanner enabled status",
			"count", len(req.GetIds()),
			"enabled", req.GetEnabled())

		if len(req.GetIds()) == 0 {
			context.GetLogger(c.UserContext()).Warn("Empty scanner ID list provided")
			return c.Status(fiber.StatusNoContent).Send(nil)
		}

		err := srv.BatchUpdateScannersEnabled(c.UserContext(), &req)
		if err != nil {
			context.GetLogger(c.UserContext()).Error("Error batch updating scanners", "error", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		context.GetLogger(c.UserContext()).Info("Successfully batch updated scanners")
		return c.Status(fiber.StatusNoContent).Send(nil)
	}
}
